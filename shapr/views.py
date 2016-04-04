from functools import wraps
from flask.ext.login import login_required, login_user, current_user, \
                            logout_user, user_logged_in
from flask import render_template, url_for, redirect, abort, request, flash
import pyotp
from . import app, db, throttler, forms
from .forms import LoginForm, UserForm, PasswordForm, SettingsForm, \
                   UpdatePasswordForm, CreateUserForm, TotpForm
from .models import User, Settings, Event
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
    if current_user.permissions == User.PERM_ADMIN:
        return redirect(url_for('admin'))
    elif current_user.permissions == User.PERM_CIRCLE:
        return redirect(url_for('circle'))
    elif current_user.permissions == User.PERM_SQUARE:
        return redirect(url_for('square'))

@app.route('/admin', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def admin():
    users = User.query.all()
    settings = Settings.query.first()
    settings_form = SettingsForm(request.form, obj=settings)
    if settings_form.validate_on_submit():
        settings_form.populate_obj(settings)
        db.session.commit()
    return render_template('admin.html', users=users,
                           settings_form=settings_form)

@app.route('/user', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def create_user():
    settings = Settings.query.first()
    form = CreateUserForm()
    if form.validate_on_submit() and \
            forms.validate_password_form(form, settings):
        user = User()
        form.populate_user(user)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('edit_user', user_id=user.id))
    return render_template('user.html', form=form)

@app.route('/user/<user_id>/', methods=['GET', 'POST'])
@perm_required(User.PERM_ADMIN)
def edit_user(user_id):
    user = User.query.get(user_id)
    settings = Settings.query.first()
    form = UserForm(request.form, obj=user)
    if form.is_submitted() and form.delete.data:
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('admin'))
    elif form.is_submitted() and form.reset_password.data:
        new_password = user.reset_password()
        flash('Temporary password is "{}"'.format(new_password))
        db.session.commit()
    elif form.validate_on_submit() and \
            forms.validate_password_form(form, settings, user):
        if form.password.data:
            return render_template('update_password.html',
                                   form=UpdatePasswordForm(request.form),
                                   user=user)
        form.populate_user(user)
        db.session.commit()
    return render_template('user.html', form=form, user=user)

@app.route('/user/<user_id>/password', methods=['POST'])
@perm_required(User.PERM_ADMIN)
def update_password(user_id):
    user = User.query.get(user_id)
    settings = Settings.query.first()
    form = UpdatePasswordForm()

    if form.validate_on_submit() and \
            forms.validate_password_form(form, settings, user):
        user.password = form.password.data
        db.session.commit()
        return redirect(url_for('edit_user', user_id=user.id))
    return render_template('update_password.html', form=form, user=user)

@app.route('/circle')
@perm_required(User.PERM_CIRCLE)
def circle():
    return render_template('circle.html')

@app.route('/square')
@perm_required(User.PERM_SQUARE)
def square():
    return render_template('square.html')

@app.route('/login', methods=['GET'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/login', methods=['POST'])
def do_login():
    settings = Settings.query.first()
    @ratelimit(limit=settings.login_throttle_count, \
               per=settings.login_throttle_period, \
               over_limit=throttle_login)
    def do_throttled_login():
        form = LoginForm()
        if form.validate_on_submit():
            user = auth_by_password(form.username.data, form.password.data)
            if user and user.active:
                if user.totp_key:
                    totp_form = TotpForm()
                    if not totp_form.validate_on_submit() \
                            or not totp_form.validate_totp_for_user(user):
                        return render_template('totp.html', form=totp_form)

                login_user(user)
                throttler.get_view_rate_limit().clear()
                user.check_password_expiration(settings)
                if user.password_reset:
                    flash('User must reset password to continue')
                    return redirect(url_for('reset_password', next=form.next.data))
                return form.redirect('index')
        return render_template('login.html', form=form)
    return do_throttled_login()

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not current_user or not current_user.password_reset:
        abort(401)
    settings = Settings.query.first()
    form = PasswordForm()
    if form.validate_on_submit() and \
            forms.validate_password_form(form, settings, current_user):
        current_user.password = form.password.data
        current_user.password_reset = False
        db.session.commit()
        return form.redirect('index')
    return render_template('password.html', form=form)

@app.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def setup_totp():
    if current_user.totp_key is None or request.method == 'POST':
        current_user.totp_key = pyotp.random_base32()
        current_user.events.append(Event(type="New TFA key",
                                         info="A new Two-Factor Authentication "\
                                              "key was generated"))
        db.session.commit()
    totp = pyotp.TOTP(current_user.totp_key)
    return render_template('setup_totp.html', totp=totp, user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@user_logged_in.connect_via(app)
def on_user_logged_in(app, user=None):
    if user is None:
        return
    user.events.append(Event(type='User Login',
                             info='This user successfuly logged in'))
    db.session.commit()
