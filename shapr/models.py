from flask_login import UserMixin
from sqlalchemy import event
import string
import random
from . import db, bcrypt

def random_password(size):
    return ''.join(random.choice(string.ascii_letters + string.digits +
                          string.punctuation)
                for _ in range(size))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    PERM_SQUARE = 0x1
    PERM_CIRCLE = 0x2
    PERM_ADMIN  = 0x4 | PERM_CIRCLE | PERM_SQUARE

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    permissions = db.Column(db.Integer, default=0, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    throttled = db.Column(db.Boolean, default=False, nullable=False)
    password_reset = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, username=None, password=None, permissions=None, **kwargs):
        self.username = username
        self.permissions = permissions
        if password:
            self.password = password

    def is_active(self):
        return self.active and not self.password_reset

    def throttle(self):
        if self.throttled:
            self.active = False
        else:
            self.throttled = True

    def reset_password(self):
        self.active = True
        self.password_reset = True
        new_password = random_password(16)
        self.password = new_password
        return new_password

@event.listens_for(User.password, 'set', retval=True)
def on_change_password(target, value, oldvalue, initiator):
    return bcrypt.generate_password_hash(value)

