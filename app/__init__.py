from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_login import current_user
import os
import dotenv

db = SQLAlchemy()

def create_app():
    dotenv.load_dotenv()
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_TYPE'] = 'filesystem'
    db.init_app(app)
    Session(app)

    # Import models so SQLAlchemy is aware of them
    from . import models

    # Register blueprints and other services
    from .routes import bp
    app.register_blueprint(bp)

    @app.context_processor
    def inject_user():
        return dict(current_user=current_user)

    return app