import os

from flask_login import login_required
from flask_migrate import Migrate

from app import create_app, db
from app.models import User, Role, Post, Permission

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
migrate = Migrate(app, db)


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Permission=Permission, Post=Post)


@app.cli.command()
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


@app.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'
