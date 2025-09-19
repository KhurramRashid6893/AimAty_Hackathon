from flask import Flask
from config import Config
from models import db
from routes import main_bp, ensure_admin_exists   # import helper defined in routes

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()
        # ensure default admin exists (seed_db usually handles booth and candidates)
        ensure_admin_exists()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
