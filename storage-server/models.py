from sqlalchemy.dialects.postgresql import UUID
from flask_sqlalchemy import SQLAlchemy
import uuid

db = SQLAlchemy()

class DirectoryFile(db.Model):
    uuid = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid1)
    name = db.Column(db.Text, nullable=False)
    mimetype = db.Column(db.String(32), nullable=False)
    path = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f"<DirectoryFile(uuid={self.uuid}, name={self.name}, type={self.mimetype}, path={self.path})>"
    