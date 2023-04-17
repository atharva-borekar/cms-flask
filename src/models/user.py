from dataclasses import dataclass
from src.app import db

@dataclass
class User(db.Model):
    __tablename__ = 'user'
    id: int
    name: str
    username: str
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    def __init__(self, name, username, password):
        self.name = name
        self.username = username
        self.password = password