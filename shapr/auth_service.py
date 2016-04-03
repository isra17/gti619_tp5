from . import bcrypt, db
from .models import User, Event

def auth_by_password(username, password):
    user = User.query.filter(User.username == username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return user
    elif user:
        user.events.append(Event(type='Failed Login',
                                 info='An unsuccessful login attempts was made ' \
                                      'to this account'))
        db.session.commit()
    return None

