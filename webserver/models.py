from sqlalchemy.dialects.postgresql import UUID
from flask_sqlalchemy import SQLAlchemy
import uuid

db = SQLAlchemy()

class Account(db.Model):
    # uuid = db.Column(UUID(), primary_key=True)
    uuid = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(32), nullable=False)
    hashed_pass = db.Column(db.String(72), nullable=False)
    
    def __repr__(self):
        return f"<User(uuid={self.uuid}, username={self.username}, pass={self.hashed_pass})>"