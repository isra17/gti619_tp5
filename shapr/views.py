from functools import wraps
from flask.ext.login import login_required, login_user, current_user, logout_user
from flask import render_template, url_for, redirect, abort, request
from . import app, db
from .forms import LoginForm, UserForm
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
    """ This view redirect to a page depending on user's permissions """
    if current_user.permissions & User.PERM_ADMIN:
        return redirect(url_for('admin'))
    elif current_user.permissions & User.PERM_CIRCLE:
        return redirect(url_for('circle'))
    elif current_user.permissions & User.PERM_SQUARE:
        return redirect(url_for('square'))

@app.route('/admin')
@perm_required(User.PERM_ADMIN)
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/user/<user_id>', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def edit_user(user_id):
    user = User.query.get(user_id)
    form = UserForm(request.form, obj=user)
    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
    return render_template('user.html', form=form)

@app.route('/user', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def create_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User()
        form.populate_obj(user)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('edit_user', user_id=user.id))
    return render_template('user.html', form=form)

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
