from flask import Flask
from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from shapr import app, db

migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

# Import models for migration
from shapr.models import *

@manager.command
def seed():
    "Add seed data to the database."
    db.session.add(User('Administrateur', 'Administrateur',
                        User.PERM_ADMIN | User.PERM_SQUARE | User.PERM_CIRCLE))
    db.session.add(User('Utilisateur1', 'Utilisateur1', User.PERM_CIRCLE))
    db.session.add(User('Utilisateur2', 'Utilisateur2', User.PERM_SQUARE))
    db.session.commit()

if __name__ == "__main__":
    manager.run()

