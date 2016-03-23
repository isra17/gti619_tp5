from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from . import config

# Init flask app.
app = Flask(__name__)
app.config.from_object(config)

# Init app database.
db = SQLAlchemy(app)

# Init login manager.
login_manager = LoginManager(app)
login_manager.login_view = '/login'
from .models import User
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(user_id)
    except:
        return None

# Load views
from . import views
