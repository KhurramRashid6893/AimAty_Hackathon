# seed_db.py
from datetime import datetime, timedelta
from app import create_app
from models import db, Admin, BoothOfficer, Candidate, DigiLockerDummy, CandidateUser, Nomination

app = create_app()
with app.app_context():
    # Drop and recreate tables
    db.drop_all()
    db.create_all()

    # ---------------- Admin ----------------
    admin = Admin(username='admin')
    admin.set_password('admin123')
    db.session.add(admin)

    # ---------------- Booth officer ----------------
    booth = BoothOfficer(username='booth', booth_number='B1')
    booth.set_password('booth123')
    db.session.add(booth)

    # ---------------- Election Candidates (10 Bihar constituencies) ----------------
    entries = [
        ('C1', 'Ram Kumar', 'BJP', 'Patna'),
        ('C2', 'Sita Devi', 'RJD', 'Gaya'),
        ('C3', 'Ajay Singh', 'JD(U)', 'Hajipur'),
        ('C4', 'Meera Sharma', 'INC', 'Purnia'),
        ('C5', 'Vikas Yadav', 'LJP', 'Nalanda'),
        ('C6', 'Raju Prasad', 'HAM', 'Muzaffarpur'),
        ('C7', 'Sunita Kumari', 'RLSP', 'Darbhanga'),
        ('C8', 'Anil Kumar', 'JAP', 'Siwan'),
        ('C9', 'Kiran Patel', 'CPI(ML)', 'Bhagalpur'),
        ('C10', 'Asad Khan', 'AIMIM', 'Samastipur'),
    ]
    for cid, name, party, const in entries:
        c = Candidate(candidate_id=cid, name=name, party=party, constituency=const)
        db.session.add(c)

    # ---------------- DigiLocker Dummy Records ----------------
    dummy_records = [
        DigiLockerDummy(
            name="Ramesh Kumar",
            dob="1985-03-15",
            aadhaar="123456789012",
            address="Ward 5, Patna",
            party="Independent",
            constituency="Patna Sahib",
            email="ramesh.kumar@example.com",
            phone="9876543210"
        ),
        DigiLockerDummy(
            name="Sushila Devi",
            dob="1978-07-22",
            aadhaar="987654321098",
            address="Sector 12, Hajipur",
            party="People’s Party",
            constituency="Hajipur",
            email="sushila.devi@example.com",
            phone="9123456780"
        ),
        DigiLockerDummy(
            name="Mohammad Ali",
            dob="1990-11-05",
            aadhaar="456789123456",
            address="Gaya City, Bihar",
            party="Progressive Front",
            constituency="Gaya",
            email="mohammad.ali@example.com",
            phone="9001122334"
        ),
    ]
    db.session.bulk_save_objects(dummy_records)

    # ---------------- Candidate User Accounts ----------------
    cand1 = CandidateUser(aadhaar="123456789012"); cand1.set_password("candidate123")
    cand2 = CandidateUser(aadhaar="987654321098"); cand2.set_password("candidate123")
    cand3 = CandidateUser(aadhaar="456789123456"); cand3.set_password("candidate123")
    db.session.add_all([cand1, cand2, cand3])
    db.session.flush()  # ensure IDs are available

    # ---------------- Sample Nominations ----------------
    now = datetime.utcnow()
    nominations = [
        Nomination(
            name="Ramesh Kumar",
            dob="1985-03-15",
            aadhaar="123456789012",
            address="Ward 5, Patna",
            party="Independent",
            constituency="Patna Sahib",
            email="ramesh.kumar@example.com",
            phone="9876543210",
            affidavit="uploads/sample.pdf",
            property_cert="uploads/sample.pdf",
            education_cert="uploads/sample.pdf",
            criminal_record="uploads/sample.pdf",
            status="Pending",
            username="123456789012",
            password=cand1.password,
            created_at=now - timedelta(days=1)  # yesterday
        ),
        Nomination(
            name="Sushila Devi",
            dob="1978-07-22",
            aadhaar="987654321098",
            address="Sector 12, Hajipur",
            party="People’s Party",
            constituency="Hajipur",
            email="sushila.devi@example.com",
            phone="9123456780",
            affidavit="uploads/sample.pdf",
            property_cert="uploads/sample.pdf",
            education_cert="uploads/sample.pdf",
            criminal_record="uploads/sample.pdf",
            status="Approved",   # ✅ Approved
            username="987654321098",
            password=cand2.password,
            created_at=now - timedelta(hours=12)  # half a day ago
        ),
        Nomination(
            name="Mohammad Ali",
            dob="1990-11-05",
            aadhaar="456789123456",
            address="Gaya City, Bihar",
            party="Progressive Front",
            constituency="Gaya",
            email="mohammad.ali@example.com",
            phone="9001122334",
            affidavit="uploads/sample.pdf",
            property_cert="uploads/sample.pdf",
            education_cert="uploads/sample.pdf",
            criminal_record="uploads/sample.pdf",
            status="Rejected",   # ✅ Rejected
            username="456789123456",
            password=cand3.password,
            created_at=now  # now
        ),
    ]
    db.session.add_all(nominations)

    # ---------------- Commit ----------------
    db.session.commit()
    print("✅ Seeded DB: admin, booth officer, 10 candidates, 3 DigiLocker dummy records, 3 candidate logins, 3 sample nominations (Pending/Approved/Rejected)")
