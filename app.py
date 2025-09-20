from flask import Flask, session
from config import Config
from models import db
from routes import main_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    app.register_blueprint(main_bp)
    
    with app.app_context():
        db.create_all()
        # Seed dummy data for DigiLocker simulation
        # You can add more entries here.

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)