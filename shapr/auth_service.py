from flask.ext.bcrypt import Bcrypt
from .models import User

def auth_by_password(username, password):
    user = User.query.filter(User.username == username).first()
    if bcrypt.check_password_hash(user.password, password):
        return user
    else:
        return None

