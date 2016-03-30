from functools import wraps
from flask.ext.login import login_required, login_user, current_user, logout_user
from flask import render_template, url_for, redirect, abort, request, flash
from . import app, db, throttler
from .forms import LoginForm, UserForm, PasswordForm
from .models import User
from .auth_service import auth_by_password
from .throttler import ratelimit

def perm_required(permissions):
    def perm_required_decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if current_user and current_user.is_active and \
                    hasattr(current_user, 'permissions') and \
                    current_user.permissions & permissions == permissions:
                return func(*args, **kwargs)
            abort(401)

        return decorated_view
    return perm_required_decorator

def throttle_login(rlimit):
    if rlimit.exceeded_again():
        return throttler.on_over_limit(rlimit)

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.username == form.username.data).first()
        if user:
            user.throttle()
            db.session.commit()
    return throttler.on_over_limit(rlimit)

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

@app.route('/user', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def create_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User()
        form.populate_user(user)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('edit_user', user_id=user.id))
    return render_template('user.html', form=form)

@app.route('/user/<user_id>', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def edit_user(user_id):
    user = User.query.get(user_id)
    form = UserForm(request.form, obj=user)
    if form.is_submitted() and form.delete.data:
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('admin'))
    elif form.is_submitted() and form.reset_password.data:
        new_password = user.reset_password()
        flash('Temporary password is "{}"'.format(new_password))
        db.session.commit()
    elif form.validate_on_submit():
        form.populate_user(user)
        db.session.commit()
    return render_template('user.html', form=form, user=user)


@app.route('/circle')
@perm_required(User.PERM_CIRCLE)
def circle():
    return 'Circle'

@app.route('/square')
@perm_required(User.PERM_SQUARE)
def square():
    return 'Square'

@app.route('/login', methods=['GET'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/login', methods=['POST'])
@ratelimit(limit=3, per=30, over_limit=throttle_login)
def do_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = auth_by_password(form.username.data, form.password.data)
        if user and user.active:
            login_user(user)
            throttler.get_view_rate_limit().clear()
            if user.password_reset:
                flash('User must reset password to continue')
                return redirect(url_for('reset_password', next=form.next.data))
            return form.redirect('index')
    return render_template('login.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not current_user or not current_user.password_reset:
        abort(401)
    form = PasswordForm()
    if form.validate_on_submit():
        current_user.password = form.password.data
        current_user.password_reset = False
        db.session.commit()
        return form.redirect('index')
    return render_template('password.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
