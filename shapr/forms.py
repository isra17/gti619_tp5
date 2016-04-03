from urllib.parse import urlparse, urljoin
from flask.ext.login import current_user
from flask_wtf import Form
from flask import request, url_for, redirect
from wtforms import StringField, PasswordField, HiddenField, SelectField, \
                    SubmitField, BooleanField, IntegerField, validators
from wtforms.validators import DataRequired, Optional, ValidationError
import string
from .models import User, Settings
from . import bcrypt

__char_groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]

def validate_password_form(form, settings, user=None):
    if not form.password.data:
        return True

    settings_validators = [validators.Length(min=settings.password_len)]
    if settings.complexe_password:
        settings_validators.append(require_complexe_password)
    if settings.password_history > 0 and user is not None:
        settings_validators.append(PasswordHistoryValidator(settings, user))
    return form.password.validate(form, settings_validators)

def require_complexe_password(form, field):
    if not is_complexe_password(field.data):
        raise ValidationError("Password must contains lowercases, uppercases, "
                              "digits and special characters.")

class PasswordHistoryValidator:
    def __init__(self, settings, user):
        self.settings = settings
        self.user = user
    def __call__(self, form, field):
        password = field.data

        if self.settings.password_history > 0:
            for history in \
                    self.user.password_history[-self.settings.password_history:]:
                if bcrypt.check_password_hash(history.password, password):
                    raise ValidationError('Password have been used in the past')

def validate_current_password(form, field):
    if not bcrypt.check_password_hash(current_user.password, field.data):
        raise ValidationError('Invalid password')

def is_complexe_password(password):
    # Check for at least one char of each group.
    if not all(any(c in group for c in password) for group in __char_groups):
        return False
    # Check for at least one char not in any group (Special char).
    if not any(all(c not in group for group in __char_groups) for c
            in password):
        return False
    return True

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_redirect_target():
    target = request.args.get('next')
    if is_safe_url(target):
        return target

class RedirectForm(Form):
    next = HiddenField()

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        if not self.next.data:
            self.next.data = get_redirect_target() or ''

    def redirect(self, endpoint='index', **values):
        if is_safe_url(self.next.data):
            return redirect(self.next.data)
        target = get_redirect_target()
        return redirect(target or url_for(endpoint, **values))

class LoginForm(RedirectForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

class PasswordForm(RedirectForm):
    password = PasswordField('password', validators=[DataRequired()])

class UpdatePasswordForm(RedirectForm):
    current_password = PasswordField('password', validators=[validate_current_password])
    password = HiddenField('password', validators=[DataRequired()])

class UserForm(Form):
    id = HiddenField()
    username = StringField('username', validators=[])
    password = PasswordField('password', validators=[])
    permissions = SelectField('permissions', choices=[
            (User.PERM_ADMIN, 'Admin'),
            (User.PERM_SQUARE, 'Square'),
            (User.PERM_CIRCLE, 'Circle'),
        ], coerce=int)
    delete = SubmitField('Delete')
    reset_password = SubmitField('Reset Password')

    def populate_user(self, user):
        if self.validate():
            for fieldname in ['password', 'permissions', 'username']:
                field = getattr(self, fieldname)
                if field.data:
                    setattr(user, fieldname, field.data)



class SettingsForm(Form):
    complexe_password = BooleanField('Require complexe password')
    password_len = IntegerField('Minimum password length')
    password_history = IntegerField('Password History')
