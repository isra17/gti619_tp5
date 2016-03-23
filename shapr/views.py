from functools import wraps
from flask.ext.login import login_required, login_user, current_user, logout_user
from flask import render_template, url_for, redirect, abort
from . import app
from .forms import LoginForm
from .models import User
from .auth_service import auth_by_password

def perm_required(permissions):
    def perm_required_decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if hasattr(current_user, 'permissions') and \
                    current_user.permissions & permissions == permissions:
                return func(*args, **kwargs)
            abort(401)

        return decorated_view
    return perm_required_decorator

@app.route('/')
@login_required
def index():
    return 'Hello ' + current_user.username

@app.route('/admin')
@perm_required(User.PERM_ADMIN)
def admin():
    return 'Admin'

@app.route('/circle')
@perm_required(User.PERM_CIRCLE)
def circle():
    return 'Circle'

@app.route('/square')
@perm_required(User.PERM_SQUARE)
def square():
    return 'Square'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = auth_by_password(form.username.data, form.password.data)
        if user:
            login_user(user)
            return form.redirect('index')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
