import base64
from dataclasses import dataclass
from src.app import db
from cryptography.fernet import Fernet
@dataclass
class User(db.Model):
    __tablename__ = 'user'
    id: int
    name: str
    username: str
    passcode: str
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    passcode = db.Column(db.String(4096), nullable=True)

    def __init__(self, name, username, password):
        self.name = name
        self.username = username
        self.password = password
        self.passcode = base64.urlsafe_b64encode(Fernet.generate_key()).decode('utf-8')