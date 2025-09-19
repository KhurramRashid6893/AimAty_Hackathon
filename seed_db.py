from app import create_app
from models import db, Admin, BoothOfficer, Candidate

app = create_app()
with app.app_context():
    db.drop_all()
    db.create_all()

    # Admin
    admin = Admin(username='admin')
    admin.set_password('admin123')
    db.session.add(admin)

    # Booth officer
    booth = BoothOfficer(username='booth', booth_number='B1')
    booth.set_password('booth123')
    db.session.add(booth)

    # Candidates for 10 Bihar constituencies
    entries = [
        ('C1','Ram Kumar','BJP','Patna'),
        ('C2','Sita Devi','RJD','Gaya'),
        ('C3','Ajay Singh','JD(U)','Hajipur'),
        ('C4','Meera Sharma','INC','Purnia'),
        ('C5','Vikas Yadav','LJP','Nalanda'),
        ('C6','Raju Prasad','HAM','Muzaffarpur'),
        ('C7','Sunita Kumari','RLSP','Darbhanga'),
        ('C8','Anil Kumar','JAP','Siwan'),
        ('C9','Kiran Patel','CPI(ML)','Bhagalpur'),
        ('C10','Asad Khan','AIMIM','Samastipur'),
    ]
    for cid, name, party, const in entries:
        c = Candidate(candidate_id=cid, name=name, party=party, constituency=const)
        db.session.add(c)

    db.session.commit()
    print('Seeded DB: admin, booth officer, 10 candidates')
