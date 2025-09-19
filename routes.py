import os
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from models import db, Voter, Candidate, Vote, Admin, BoothOfficer, BallotStatus, MismatchLog
from utils import save_face_image, encode_face_from_file, compare_faces

main_bp = Blueprint('main', __name__)

# --- Helpers ---
def ensure_admin_exists():
    """Ensure a default admin exists."""
    admin = Admin.query.filter_by(username='admin').first()
    if not admin:
        admin = Admin(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

def activate_ballot_for_voter(voter_id, booth_number='B1', note='auto'):
    """Activate ballot for a voter (invalidate old ballots)."""
    # deactivate existing active ballot for same voter+booth
    BallotStatus.query.filter_by(voter_id=voter_id, booth_number=booth_number, is_active=True).update({'is_active': False})
    bs = BallotStatus(voter_id=voter_id, booth_number=booth_number, is_active=True, timestamp=datetime.utcnow())
    db.session.add(bs)
    db.session.commit()
    return bs

# --- Routes ---
@main_bp.route('/')
def index():
    return render_template('index.html')

# ---------------- Signup ----------------
@main_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        aadhaar = request.form['aadhaar']
        voter_id = request.form['voter_id']
        face = request.files.get('face')

        if Voter.query.filter((Voter.voter_id==voter_id)|(Voter.aadhaar==aadhaar)).first():
            flash('Voter ID or Aadhaar already exists', 'danger')
            return redirect(url_for('main.signup'))

        face_path = None
        if face:
            face_path = save_face_image(face, voter_id)

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

    return render_template('signup.html')

# ---------------- Login ----------------
@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')

        if role == 'admin':
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                session['role'] = 'admin'
                return redirect(url_for('main.admin_dashboard'))
            flash('Invalid admin credentials', 'danger')

        elif role == 'booth':
            booth = BoothOfficer.query.filter_by(username=username).first()
            if booth and booth.check_password(password):
                session['role'] = 'booth'
                session['booth_number'] = booth.booth_number
                return redirect(url_for('main.booth_dashboard'))
            flash('Invalid booth officer credentials', 'danger')

        elif role == 'voter':
            voter = Voter.query.filter_by(voter_id=username).first()
            if voter:
                session['role'] = 'voter'
                session['voter_id'] = voter.voter_id
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
        { 'father_name': 'Ramesh Kumar', 'gender': 'Male', 'address': 'Ward 5, Patna', 'assembly': 'Patna Sahib', 'part_no': '12', 'serial_no': '45' },
        { 'father_name': 'Mohammad Ali', 'gender': 'Male', 'address': 'Gaya City', 'assembly': 'Gaya', 'part_no': '7', 'serial_no': '101' },
        { 'father_name': 'Sushila Devi', 'gender': 'Female', 'address': 'Hajipur', 'assembly': 'Hajipur', 'part_no': '3', 'serial_no': '22' },
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
        return jsonify({'status':'error','message':'face image required'}), 400

    # Save temporary capture
    tmp_name = secure_filename(f"tmp_{uuid.uuid4().hex}.jpg")
    tmp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], tmp_name)
    file.save(tmp_path)

    matched_voter = None
    voters = Voter.query.all()

    # try to encode unknown once outside loop to save ops
    unknown_enc = encode_face_from_file(tmp_path)

    for voter in voters:
        if not voter.face_image:
            continue
        known_enc = encode_face_from_file(voter.face_image)
        if known_enc is not None and unknown_enc is not None:
            try:
                if compare_faces(known_enc, unknown_enc):
                    matched_voter = voter
                    break
            except Exception:
                pass
        else:
            # fallback: naive file match (only exact same file)
            try:
                with open(voter.face_image,'rb') as f1, open(tmp_path,'rb') as f2:
                    if f1.read() == f2.read():
                        matched_voter = voter
                        break
            except Exception:
                pass

    # cleanup tmp
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    if matched_voter:
        activate_ballot_for_voter(matched_voter.voter_id, booth_number, note='face-verified')
        return jsonify({'status':'ok','message':f'✅ Welcome {matched_voter.name} (ID: {matched_voter.voter_id}). Ballot activated','activate':True})
    else:
        # log mismatch for audit (no aadhaar available here)
        ml = MismatchLog(aadhaar='', voter_id='', note='FACE_MISMATCH', timestamp=datetime.utcnow())
        db.session.add(ml)
        db.session.commit()
        return jsonify({'status':'mismatch','message':'❌ No voter match found. Ask booth officer for manual override.','activate':False})

# ---------------- Manual Override ----------------
# Manual override (form)
@main_bp.route('/manual_override', methods=['POST'])
def manual_override():
    aadhaar = request.form.get('aadhaar')
    voter_id = request.form.get('voter_id')
    booth_number = request.form.get('booth_number') or 'B1'
    note = request.form.get('note') or 'Manual override by officer'

    voter = Voter.query.filter_by(voter_id=voter_id).first()
    created_new = False
    if not voter:
        # Create new voter if not found
        voter = Voter(name="Unknown", dob=datetime.utcnow().date(),
                      aadhaar=aadhaar or '', voter_id=voter_id, face_image=None)
        db.session.add(voter)
        db.session.commit()
        created_new = True

    # Log mismatch / override; if created_new mark specially so admin can see
    ml_note = note
    if created_new:
        ml_note = f"NEW_VOTER_CREATED: {note}"
    ml = MismatchLog(aadhaar=aadhaar or '', voter_id=voter_id, note=ml_note, timestamp=datetime.utcnow())
    db.session.add(ml)

    activate_ballot_for_voter(voter_id, booth_number, note=note)
    db.session.commit()
    flash('Ballot activated (new voter created if not found).', 'success')
    return redirect(url_for('main.booth_dashboard'))


# Manual override via AJAX
@main_bp.route('/api/manual_override', methods=['POST'])
def api_manual_override():
    data = request.get_json() or {}
    aadhaar = data.get('aadhaar')
    voter_id = data.get('voter_id')
    booth_number = data.get('booth_number') or 'B1'
    note = data.get('note') or 'Manual override (ajax)'

    voter = Voter.query.filter_by(voter_id=voter_id).first()
    created_new = False
    if not voter:
        voter = Voter(name="Unknown", dob=datetime.utcnow().date(),
                      aadhaar=aadhaar or '', voter_id=voter_id, face_image=None)
        db.session.add(voter)
        db.session.commit()
        created_new = True

    ml_note = note
    if created_new:
        ml_note = f"NEW_VOTER_CREATED: {note}"
    ml = MismatchLog(aadhaar=aadhaar or '', voter_id=voter_id, note=ml_note, timestamp=datetime.utcnow())
    db.session.add(ml)

    activate_ballot_for_voter(voter_id, booth_number, note=note)
    db.session.commit()

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
        return jsonify({'status':'error','message':'voter_id and candidate_id required'}), 400

    bs = BallotStatus.query.filter_by(voter_id=voter_id, booth_number=booth_number, is_active=True).first()
    if not bs:
        return jsonify({'status':'error','message':'Ballot not active'}), 403

    receipt = str(uuid.uuid4())
    vote = Vote(voter_id=voter_id, candidate_id=candidate_id, booth_number=booth_number, receipt=receipt)
    db.session.add(vote)

    # mark this ballot as consumed
    bs.is_active = False
    db.session.commit()

    return jsonify({'status':'ok','message':'Vote recorded','receipt':receipt})

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
    party_tally = db.session.query(Candidate.party, db.func.count(Vote.id)).join(Vote, Candidate.candidate_id==Vote.candidate_id).group_by(Candidate.party).all()
    constituency_tally = db.session.query(Candidate.constituency, db.func.count(Vote.id)).join(Vote, Candidate.candidate_id==Vote.candidate_id).group_by(Candidate.constituency).all()

    return render_template('admin_dashboard.html',
                           total_votes=total_votes,
                           candidate_results=candidate_results,
                           party_tally=party_tally,
                           constituency_tally=constituency_tally)

@main_bp.route('/booth_dashboard')
def booth_dashboard():
    if session.get('role') not in ('booth','admin'):
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
            'type':'ballot',
            'voter_id': b.voter_id,
            'booth': b.booth_number,
            'time': b.timestamp.isoformat(),
            'status': 'activated' if b.is_active else 'deactivated'
        })
    for v in votes:
        activity.append({
            'type':'vote',
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
                'type':'new_voter',
                'voter_id': m.voter_id,
                'aadhaar': m.aadhaar,
                'note': m.note,
                'time': m.timestamp.isoformat()
            })
        else:
            activity.append({
                'type':'mismatch',
                'voter_id': m.voter_id,
                'aadhaar': m.aadhaar,
                'note': m.note,
                'time': m.timestamp.isoformat()
            })

    # sort and return limited
    activity.sort(key=lambda x: x['time'], reverse=True)
    return jsonify(activity[:30])

# ---------------- Static Uploads ----------------
@main_bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
