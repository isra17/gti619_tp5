from flask_login import UserMixin
from . import db, bcrypt

class User(UserMixin, db.Model):
    __tablename__ = "users"
    PERM_SQUARE = 0x1
    PERM_CIRCLE = 0x2
    PERM_ADMIN  = 0x4

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    permissions = db.Column(db.Integer, default=0, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

    def __init__(self, username, password, permissions):
        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        self.permissions = permissions

    def is_active(self):
        return self.active

