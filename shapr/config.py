# Default development config
import os
DEBUG = os.environ.get('DEBUG', '0') == '1'
SECRET_KEY = os.environ.get('SECRET_KEY', '\x00'*32)
SQLALCHEMY_DATABASE_URI = \
        os.environ.get('DATABASE_URL', 'sqlite:////tmp/shapr.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
PASSWORD_ALGO = 'bcrypt'
