from flask_login import UserMixin
from . import db
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    email: str = db.Column(db.String(100), unique=True)
    password: str = db.Column(db.String(100))
    name: str = db.Column(db.String(1000))

    def __init__(self, email: str, name: str, password: str) -> None:
        self.email = email
        self.name = name
        self.password = generate_password_hash(password, method="sha256")

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password, password)
