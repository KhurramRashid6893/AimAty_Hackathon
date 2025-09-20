# ak/routes.py  (Blueprint: main_bp)
# Full rewritten routes file (fixed bugs + candidate nomination & ECI approval)
import os
import uuid
from datetime import datetime
from functools import wraps
from models import db, Voter, Candidate, Vote, Admin, BoothOfficer, BallotStatus, MismatchLog, Nomination, DigiLockerDummy, CandidateUser

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session,
    current_app, send_from_directory, jsonify, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Import your models - ensure models.py contains these classes:
from models import (
    db,
    Voter,
    Candidate,
    Vote,
    Admin,
    BoothOfficer,
    BallotStatus,
    MismatchLog,
    Nomination,
    DigiLockerDummy
)

# Utility functions for face handling (you already had these in utils)
from utils import save_face_image, encode_face_from_file, compare_faces

main_bp = Blueprint('main', __name__)

# Allowed upload file extensions (for candidate documents)
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
DEFAULT_CANDIDATE_PASSWORD = "candidate123"
ECI_USERNAME = "eci"
ECI_PASSWORD = "eci123"


# ---------------- Helpers ----------------
def allowed_file(filename):
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS


def ensure_upload_folder():
    """Ensure the configured upload folder exists."""
    upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
    if not os.path.isabs(upload_folder):
        # Make path relative to app root if not absolute
        upload_folder = os.path.join(current_app.root_path, upload_folder)
    os.makedirs(upload_folder, exist_ok=True)
    # store normalized path back for consistency
    current_app.config['UPLOAD_FOLDER'] = upload_folder
    return upload_folder


def save_uploaded_file(storage_file, subfolder=""):
    """
    Save a Werkzeug FileStorage object into the upload folder with a unique name.
    Returns the relative path (from the upload folder) saved to DB or the absolute path,
    whichever your application expects. Here we save the filename (uuid_prefixed)
    and return the URL-path friendly filename for send_from_directory usage.
    """
    if not storage_file:
        return None
    if storage_file.filename == '':
        return None
    if not allowed_file(storage_file.filename):
        return None

    filename = secure_filename(storage_file.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    upload_folder = ensure_upload_folder()

    # Allow optional subfolder under upload folder for better organization
    if subfolder:
        folder = os.path.join(upload_folder, secure_filename(subfolder))
        os.makedirs(folder, exist_ok=True)
    else:
        folder = upload_folder

    save_path = os.path.join(folder, unique_name)
    storage_file.save(save_path)

    # Return path relative to upload folder (useful with send_from_directory)
    rel_path = os.path.relpath(save_path, upload_folder)
    return rel_path.replace("\\", "/")  # normalize for windows paths


def ensure_admin_exists():
    """Ensure a default admin exists (username: admin / password: admin123)."""
    admin = Admin.query.filter_by(username='admin').first()
    if not admin:
        admin = Admin(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        current_app.logger.info("Default admin created: username=admin password=admin123")


def require_eci(func):
    """Decorator that requires ECI session to access route."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('eci') and session.get('role') != 'admin':
            flash('Please login as ECI to access this page', 'warning')
            return redirect(url_for('main.eci_login'))
        return func(*args, **kwargs)
    return wrapper


def activate_ballot_for_voter(voter_id, booth_number='B1', note='auto'):
    """Activate ballot for a voter (deactivate previous active ballot for that voter+booth)."""
    # Deactivate existing active ballot for same voter+booth
    BallotStatus.query.filter_by(voter_id=voter_id, booth_number=booth_number, is_active=True).update({'is_active': False})
    bs = BallotStatus(voter_id=voter_id, booth_number=booth_number, is_active=True, timestamp=datetime.utcnow())
    db.session.add(bs)
    db.session.commit()
    return bs


# ---------------- Routes ----------------
@main_bp.before_app_first_request
def startup_checks():
    """Run a few safety checks on startup (create upload folder, admin)."""
    try:
        ensure_upload_folder()
    except Exception:
        current_app.logger.exception("Could not ensure upload folder.")
    try:
        ensure_admin_exists()
    except Exception:
        current_app.logger.exception("Could not ensure admin user.")


# Homepage
@main_bp.route("/", methods=["GET"])
def index():
    # ensure admin and upload folder exists (redundant but safe)
    ensure_admin_exists()
    ensure_upload_folder()
    return render_template("index.html")


# ---------------- Candidate Nomination ----------------
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

@main_bp.route("/candidates", methods=["GET", "POST"])
def candidates():
    if request.method == "POST":
        try:
            # --- Handle uploads ---
            files = {}
            upload_dir = os.path.join(current_app.root_path, "uploads")
            os.makedirs(upload_dir, exist_ok=True)

            for f in ["affidavit", "property_cert", "education_cert", "criminal_record"]:
                file = request.files.get(f)
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    filepath = os.path.join("uploads", filename)
                    file.save(os.path.join(current_app.root_path, filepath))
                    files[f] = filepath
                else:
                    files[f] = None  # allow None if missing

            # --- Create new nomination ---
            new_nom = Nomination(
                name=request.form["name"],
                dob=request.form["dob"],
                aadhaar=request.form["aadhaar"],
                address=request.form["address"],
                party=request.form["party"],
                constituency=request.form["constituency"],
                email=request.form["email"],
                phone=request.form["phone"],
                affidavit=files["affidavit"],
                property_cert=files["property_cert"],
                education_cert=files["education_cert"],
                criminal_record=files["criminal_record"],
                status="Pending",
                username=request.form["aadhaar"],  # Aadhaar = login username
                password=generate_password_hash("candidate123")
            )

            db.session.add(new_nom)
            db.session.commit()

            flash("✅ Nomination submitted successfully! (Default password: candidate123)", "success")
            return redirect(url_for("main.candidate_dashboard"))

        except Exception as e:
            db.session.rollback()
            flash(f"❌ Failed to submit nomination. Error: {str(e)}", "danger")

    return render_template("candidates.html")


@main_bp.route("/api/digilocker/<aadhaar>", methods=["GET"])
def api_digilocker_get(aadhaar):
    """Return DigiLocker dummy record by aadhaar (JSON) for client autofill."""
    record = DigiLockerDummy.query.filter_by(aadhaar=str(aadhaar)).first()
    if not record:
        return jsonify({"found": False}), 404
    return jsonify({
        "found": True,
        "name": record.name,
        "dob": record.dob,
        "aadhaar": record.aadhaar,
        "address": record.address,
        "party": record.party,
        "constituency": record.constituency,
        "email": record.email,
        "phone": record.phone
    })


# ---------------- Candidate Authentication & Dashboard ----------------
# ---------------- Candidate Signup ----------------
@main_bp.route("/candidate_signup", methods=["GET", "POST"])
def candidate_signup():
    if request.method == "POST":
        aadhaar = request.form["aadhaar"]
        password = request.form["password"]

        # prevent duplicate
        if CandidateUser.query.filter_by(aadhaar=aadhaar).first():
            flash("Aadhaar already registered", "danger")
            return redirect(url_for("main.candidate_signup"))

        cand = CandidateUser(aadhaar=aadhaar)
        cand.set_password(password)
        db.session.add(cand)
        db.session.commit()

        flash("Signup successful! Please login.", "success")
        return redirect(url_for("main.candidate_login"))

    return render_template("candidate_signup.html")


# ---------------- Candidate Login ----------------
@main_bp.route("/candidate_login", methods=["GET", "POST"])
def candidate_login():
    if request.method == "POST":
        aadhaar = request.form["aadhaar"]
        password = request.form["password"]

        cand = CandidateUser.query.filter_by(aadhaar=aadhaar).first()
        if cand and cand.check_password(password):
            session["candidate_id"] = cand.id
            flash("Login successful", "success")
            return redirect(url_for("main.candidate_dashboard"))
        else:
            flash("Invalid Aadhaar or password", "danger")

    return render_template("candidate_login.html")


# ---------------- Candidate Dashboard ----------------
@main_bp.route("/candidate_dashboard")
def candidate_dashboard():
    if "candidate_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("main.candidate_login"))

    cand = CandidateUser.query.get(session["candidate_id"])
    nomination = Nomination.query.filter_by(aadhaar=cand.aadhaar).first()

    return render_template("candidate_dashboard.html", cand=cand, nomination=nomination)


# ---------------- Candidate Logout ----------------
@main_bp.route("/candidate_logout")
def candidate_logout():
    session.pop("candidate_id", None)
    flash("Logged out successfully", "info")
    return redirect(url_for("main.index"))

# ---------------- ECI Admin (fixed credentials) ----------------
@main_bp.route("/login_choice")
def login_choice():
    """Page showing login options: candidate / ECI"""
    return render_template("login_choice.html")


@main_bp.route("/eci_login", methods=["GET", "POST"])
def eci_login():
    """
    ECI login — uses fixed credentials: eci / eci123
    (For demo only.)
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ECI_USERNAME and password == ECI_PASSWORD:
            session.clear()
            session['eci'] = True
            session['role'] = 'eci'
            flash('Logged in as ECI', 'success')
            return redirect(url_for('main.eci_dashboard'))
        flash('Invalid ECI credentials', 'danger')
    return render_template('eci_login.html')


@main_bp.route("/eci_dashboard")
def eci_dashboard():
    candidates = Nomination.query.order_by(Nomination.created_at.desc()).all()
    return render_template("eci_dashboard.html", candidates=candidates)


@main_bp.route("/eci/view/<int:id>")
@require_eci
def eci_view_candidate(id):
    """View single nomination details + links to uploaded docs"""
    cand = Nomination.query.get_or_404(id)
    return render_template("eci_view.html", candidate=cand)


@main_bp.route("/approve/<int:id>", methods=["POST", "GET"])
@require_eci
def approve_candidate(id):
    cand = Nomination.query.get_or_404(id)
    cand.status = "Approved"
    cand.reviewed_at = datetime.utcnow()
    cand.reviewed_by = session.get('role') or 'eci'
    db.session.commit()
    flash(f"Candidate {cand.name} approved.", "success")
    return redirect(url_for("main.eci_dashboard"))


@main_bp.route("/reject/<int:id>", methods=["POST", "GET"])
@require_eci
def reject_candidate(id):
    cand = Nomination.query.get_or_404(id)
    cand.status = "Rejected"
    cand.reviewed_at = datetime.utcnow()
    cand.reviewed_by = session.get('role') or 'eci'
    db.session.commit()
    flash(f"Candidate {cand.name} rejected.", "warning")
    return redirect(url_for("main.eci_dashboard"))


# ---------------- Signup (Voter) ----------------
@main_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        dob = request.form.get('dob', '').strip()
        aadhaar = request.form.get('aadhaar', '').strip()
        voter_id = request.form.get('voter_id', '').strip()
        face = request.files.get('face')

        if not (name and dob and aadhaar and voter_id):
            flash('Please provide name, dob, aadhaar and voter_id', 'danger')
            return redirect(url_for('main.signup'))

        if Voter.query.filter((Voter.voter_id == voter_id) | (Voter.aadhaar == aadhaar)).first():
            flash('Voter ID or Aadhaar already exists', 'danger')
            return redirect(url_for('main.signup'))

        face_path = None
        if face:
            try:
                face_path = save_face_image(face, voter_id)
            except Exception:
                current_app.logger.exception("Failed to save face image")
                face_path = None

        try:
            voter = Voter(
                name=name,
                dob=datetime.strptime(dob, '%Y-%m-%d').date(),
                aadhaar=aadhaar,
                voter_id=voter_id,
                face_image=face_path
            )
            db.session.add(voter)
            db.session.commit()
            flash('Signup successful. You may now proceed to face scan.', 'success')
            return redirect(url_for('main.index'))
        except Exception:
            current_app.logger.exception("Failed to create voter")
            db.session.rollback()
            flash('Error creating voter', 'danger')
            return redirect(url_for('main.signup'))

    return render_template('signup.html')


# ---------------- Generic Login (admin/booth/voter) ----------------
@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if role == 'admin':
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                session.clear()
                session['role'] = 'admin'
                session['admin_id'] = admin.id
                flash('Logged in as admin', 'success')
                return redirect(url_for('main.admin_dashboard'))
            flash('Invalid admin credentials', 'danger')

        elif role == 'booth':
            booth = BoothOfficer.query.filter_by(username=username).first()
            if booth and booth.check_password(password):
                session.clear()
                session['role'] = 'booth'
                session['booth_number'] = booth.booth_number
                session['booth_id'] = booth.id
                flash('Logged in as booth officer', 'success')
                return redirect(url_for('main.booth_dashboard'))
            flash('Invalid booth officer credentials', 'danger')

        elif role == 'voter':
            voter = Voter.query.filter_by(voter_id=username).first()
            if voter:
                session.clear()
                session['role'] = 'voter'
                session['voter_id'] = voter.voter_id
                session['voter_db_id'] = voter.id
                flash('Logged in as voter', 'success')
                return redirect(url_for('main.voter_dashboard'))
            flash('Voter not found', 'danger')

    return render_template('login.html')


@main_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('main.index'))


# ---------------- Voter Dashboard ----------------
@main_bp.route('/voter_dashboard')
def voter_dashboard():
    if session.get('role') != 'voter':
        flash('Please login as voter', 'warning')
        return redirect(url_for('main.login'))
    voter = Voter.query.filter_by(voter_id=session.get('voter_id')).first()
    dummy_details = [
        {'father_name': 'Ramesh Kumar', 'gender': 'Male', 'address': 'Ward 5, Patna', 'assembly': 'Patna Sahib', 'part_no': '12', 'serial_no': '45'},
    ]
    return render_template('voter_dashboard.html', voter=voter, dummy_details=dummy_details)


# ---------------- Face Scan Machine ----------------
@main_bp.route('/voter_face_scan')
def voter_face_scan_page():
    return render_template('voter_face_scan.html')


@main_bp.route('/api/face_scan', methods=['POST'])
def api_face_scan():
    booth_number = request.form.get('booth_number') or 'B1'
    file = request.files.get('face')
    if not file:
        return jsonify({'status': 'error', 'message': 'face image required'}), 400

    # Save temporary capture
    tmp_name = secure_filename(f"tmp_{uuid.uuid4().hex}.jpg")
    upload_folder = ensure_upload_folder()
    tmp_path = os.path.join(upload_folder, tmp_name)
    try:
        file.save(tmp_path)
    except Exception:
        current_app.logger.exception("Failed to save tmp face image")
        return jsonify({'status': 'error', 'message': 'failed to save image'}), 500

    matched_voter = None
    voters = Voter.query.all()

    # try to encode unknown once outside loop to save ops
    unknown_enc = None
    try:
        unknown_enc = encode_face_from_file(tmp_path)
    except Exception:
        current_app.logger.exception("Failed to encode unknown face")

    for voter in voters:
        if not voter.face_image:
            continue
        try:
            known_enc = encode_face_from_file(voter.face_image)
        except Exception:
            known_enc = None

        if known_enc is not None and unknown_enc is not None:
            try:
                if compare_faces(known_enc, unknown_enc):
                    matched_voter = voter
                    break
            except Exception:
                # if encoding or compare errors, continue
                current_app.logger.debug("Face compare error", exc_info=True)
                continue
        else:
            # fallback: naive file match (only exact same file content)
            try:
                upload_folder = ensure_upload_folder()
                known_path = os.path.join(upload_folder, voter.face_image) if not os.path.isabs(voter.face_image) else voter.face_image
                with open(known_path, 'rb') as f1, open(tmp_path, 'rb') as f2:
                    if f1.read() == f2.read():
                        matched_voter = voter
                        break
            except Exception:
                continue

    # cleanup tmp
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    if matched_voter:
        activate_ballot_for_voter(matched_voter.voter_id, booth_number, note='face-verified')
        return jsonify({'status': 'ok', 'message': f'✅ Welcome {matched_voter.name} (ID: {matched_voter.voter_id}). Ballot activated', 'activate': True})
    else:
        # log mismatch for audit (no aadhaar available here)
        try:
            ml = MismatchLog(aadhaar='', voter_id='', note='FACE_MISMATCH', timestamp=datetime.utcnow())
            db.session.add(ml)
            db.session.commit()
        except Exception:
            current_app.logger.exception("Failed to log mismatch")
            db.session.rollback()
        return jsonify({'status': 'mismatch', 'message': '❌ No voter match found. Ask booth officer for manual override.', 'activate': False})


# ---------------- Manual Override ----------------
@main_bp.route('/manual_override', methods=['POST'])
def manual_override():
    aadhaar = request.form.get('aadhaar')
    voter_id = request.form.get('voter_id')
    booth_number = request.form.get('booth_number') or 'B1'
    note = request.form.get('note') or 'Manual override by officer'

    if not voter_id:
        flash('voter_id is required for manual override', 'danger')
        return redirect(url_for('main.booth_dashboard'))

    voter = Voter.query.filter_by(voter_id=voter_id).first()
    created_new = False
    if not voter:
        # Create new voter if not found
        try:
            voter = Voter(name="Unknown", dob=datetime.utcnow().date(),
                          aadhaar=aadhaar or '', voter_id=voter_id, face_image=None)
            db.session.add(voter)
            db.session.commit()
            created_new = True
        except Exception:
            current_app.logger.exception("Failed to create voter in manual override")
            db.session.rollback()
            flash('Failed to create new voter record', 'danger')
            return redirect(url_for('main.booth_dashboard'))

    # Log mismatch / override; if created_new mark specially so admin can see
    ml_note = note
    if created_new:
        ml_note = f"NEW_VOTER_CREATED: {note}"
    try:
        ml = MismatchLog(aadhaar=aadhaar or '', voter_id=voter_id, note=ml_note, timestamp=datetime.utcnow())
        db.session.add(ml)
    except Exception:
        current_app.logger.exception("Failed to add mismatch log")

    activate_ballot_for_voter(voter_id, booth_number, note=note)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to commit manual override")
        flash('Error during manual override', 'danger')
        return redirect(url_for('main.booth_dashboard'))

    flash('Ballot activated (new voter created if not found).', 'success')
    return redirect(url_for('main.booth_dashboard'))


@main_bp.route('/api/manual_override', methods=['POST'])
def api_manual_override():
    data = request.get_json() or {}
    aadhaar = data.get('aadhaar')
    voter_id = data.get('voter_id')
    booth_number = data.get('booth_number') or 'B1'
    note = data.get('note') or 'Manual override (ajax)'

    if not voter_id:
        return jsonify({'status': 'error', 'message': 'voter_id required'}), 400

    voter = Voter.query.filter_by(voter_id=voter_id).first()
    created_new = False
    if not voter:
        try:
            voter = Voter(name="Unknown", dob=datetime.utcnow().date(),
                          aadhaar=aadhaar or '', voter_id=voter_id, face_image=None)
            db.session.add(voter)
            db.session.commit()
            created_new = True
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to create new voter (api manual override)")
            return jsonify({'status': 'error', 'message': 'failed to create voter'}), 500

    ml_note = note
    if created_new:
        ml_note = f"NEW_VOTER_CREATED: {note}"
    try:
        ml = MismatchLog(aadhaar=aadhaar or '', voter_id=voter_id, note=ml_note, timestamp=datetime.utcnow())
        db.session.add(ml)
    except Exception:
        current_app.logger.exception("Failed to add mismatch log (api)")

    activate_ballot_for_voter(voter_id, booth_number, note=note)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to commit changes (api manual override)")
        return jsonify({'status': 'error', 'message': 'failed to commit override'}), 500

    return jsonify({'status': 'ok', 'message': 'Ballot activated (new voter created if not found)', 'created_new': created_new})


# ---------------- Ballot Machine ----------------
@main_bp.route('/ballot_machine_viewer/<booth_number>')
def ballot_machine_page(booth_number):
    return render_template('ballot_machine.html', booth_number=booth_number)


@main_bp.route('/api/poll_ballot/<booth_number>')
def api_poll_ballot(booth_number):
    """
    Return the oldest active ballot in queue for this booth (FIFO).
    """
    active = BallotStatus.query.filter_by(booth_number=booth_number, is_active=True).order_by(BallotStatus.timestamp.asc()).first()
    if not active:
        return jsonify({'active': False})

    voter = Voter.query.filter_by(voter_id=active.voter_id).first()
    candidates = Candidate.query.all()
    cands = [{'candidate_id': c.candidate_id, 'name': c.name, 'party': c.party, 'constituency': c.constituency} for c in candidates]

    return jsonify({
        'active': True,
        'voter_id': active.voter_id,
        'voter_name': voter.name if voter else "Unknown",
        'candidates': cands
    })


@main_bp.route('/api/cast_vote', methods=['POST'])
def api_cast_vote():
    data = request.get_json() or {}
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')
    booth_number = data.get('booth_number') or 'B1'
    if not (voter_id and candidate_id):
        return jsonify({'status': 'error', 'message': 'voter_id and candidate_id required'}), 400

    bs = BallotStatus.query.filter_by(voter_id=voter_id, booth_number=booth_number, is_active=True).first()
    if not bs:
        return jsonify({'status': 'error', 'message': 'Ballot not active'}), 403

    # Prevent duplicate votes by the same active ballot: create Vote then deactivate ballot
    try:
        receipt = str(uuid.uuid4())
        vote = Vote(voter_id=voter_id, candidate_id=candidate_id, booth_number=booth_number, receipt=receipt, timestamp=datetime.utcnow())
        db.session.add(vote)

        # mark this ballot as consumed
        bs.is_active = False
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to record vote")
        return jsonify({'status': 'error', 'message': 'failed to record vote'}), 500

    return jsonify({'status': 'ok', 'message': 'Vote recorded', 'receipt': receipt})


# ---------------- Receipt Printer ----------------
@main_bp.route('/receipt_viewer/<booth_number>')
def receipt_page(booth_number):
    return render_template('receipt.html', booth_number=booth_number)


@main_bp.route('/api/poll_receipt/<booth_number>')
def api_poll_receipt(booth_number):
    vote = Vote.query.filter_by(booth_number=booth_number).order_by(Vote.timestamp.desc()).first()
    if not vote:
        return jsonify({'has': False})
    candidate = Candidate.query.filter_by(candidate_id=vote.candidate_id).first()
    return jsonify({
        'has': True,
        'receipt': vote.receipt,
        'voter_id': vote.voter_id,
        'candidate_id': vote.candidate_id,
        'candidate_name': candidate.name if candidate else vote.candidate_id,
        'booth_number': vote.booth_number,
        'timestamp': vote.timestamp.isoformat()
    })


# ---------------- Dashboards ----------------
@main_bp.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('main.login'))
    # compute tallies for template display (optional: can be loaded via AJAX too)
    total_votes = Vote.query.count()
    candidate_tally = db.session.query(Vote.candidate_id, db.func.count(Vote.id)).group_by(Vote.candidate_id).all()
    candidate_map = {c.candidate_id: c for c in Candidate.query.all()}
    candidate_results = []
    for cid, cnt in candidate_tally:
        candidate = candidate_map.get(cid)
        candidate_results.append({'candidate': candidate, 'count': cnt})
    party_tally = db.session.query(Candidate.party, db.func.count(Vote.id)).join(Vote, Candidate.candidate_id == Vote.candidate_id).group_by(Candidate.party).all()
    constituency_tally = db.session.query(Candidate.constituency, db.func.count(Vote.id)).join(Vote, Candidate.candidate_id == Vote.candidate_id).group_by(Candidate.constituency).all()

    return render_template('admin_dashboard.html',
                           total_votes=total_votes,
                           candidate_results=candidate_results,
                           party_tally=party_tally,
                           constituency_tally=constituency_tally)


@main_bp.route('/booth_dashboard')
def booth_dashboard():
    if session.get('role') not in ('booth', 'admin'):
        flash('Please login as booth officer or admin', 'warning')
        return redirect(url_for('main.login'))
    return render_template('booth_dashboard.html')


# ---------------- Activity Feed ----------------
@main_bp.route('/api/activity_feed')
def api_activity_feed():
    """
    Return merged recent activity: ballots, votes, mismatch logs (including new-voter created).
    Sorted by time desc.
    """
    # fetch recent items
    ballots = BallotStatus.query.order_by(BallotStatus.timestamp.desc()).limit(20).all()
    votes = Vote.query.order_by(Vote.timestamp.desc()).limit(20).all()
    mismatches = MismatchLog.query.order_by(MismatchLog.timestamp.desc()).limit(20).all()

    activity = []
    for b in ballots:
        activity.append({
            'type': 'ballot',
            'voter_id': b.voter_id,
            'booth': b.booth_number,
            'time': b.timestamp.isoformat(),
            'status': 'activated' if b.is_active else 'deactivated'
        })
    for v in votes:
        activity.append({
            'type': 'vote',
            'voter_id': v.voter_id,
            'candidate_id': v.candidate_id,
            'booth': v.booth_number,
            'time': v.timestamp.isoformat(),
            'receipt': v.receipt
        })
    for m in mismatches:
        # detect new voter creation if note contains NEW_VOTER_CREATED
        if m.note and m.note.startswith('NEW_VOTER_CREATED'):
            activity.append({
                'type': 'new_voter',
                'voter_id': m.voter_id,
                'aadhaar': m.aadhaar,
                'note': m.note,
                'time': m.timestamp.isoformat()
            })
        else:
            activity.append({
                'type': 'mismatch',
                'voter_id': m.voter_id,
                'aadhaar': m.aadhaar,
                'note': m.note,
                'time': m.timestamp.isoformat()
            })

    # sort and return limited
    activity.sort(key=lambda x: x['time'], reverse=True)
    return jsonify(activity[:30])


# ---------------- Static Uploads (serve) ----------------
@main_bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """
    Serve files from the upload folder. filename should be relative to upload folder.
    NOTE: In production, let your web server serve static files instead.
    """
    upload_folder = ensure_upload_folder()
    # Normalize path and prevent directory traversal
    safe_path = secure_filename(filename)
    try:
        # send_from_directory accepts a path relative to upload_folder
        return send_from_directory(upload_folder, safe_path, as_attachment=False)
    except Exception:
        current_app.logger.exception("Failed to serve uploaded file")
        abort(404)
