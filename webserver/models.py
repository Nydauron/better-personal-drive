from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.types import TypeDecorator, LargeBinary
from flask_sqlalchemy import SQLAlchemy
import uuid

db = SQLAlchemy()

class GUID(TypeDecorator):
    """Platform-independent GUID type.

    Uses Postgresql's UUID type, otherwise uses
    LargeBinary(16), storing as binary values.

    """
    impl = LargeBinary
    
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(LargeBinary(16))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            if not isinstance(value, uuid.UUID):
                return uuid.UUID(bytes=value)
            else:
                return value
        else:
            if not isinstance(value, uuid.UUID):
                return value
            else:
                return value.bytes

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return uuid.UUID(bytes=value)

class Account(db.Model):
    uuid = db.Column(GUID(), primary_key=True, default=uuid.uuid1)
    username = db.Column(db.String(32), nullable=False)
    hashed_pass = db.Column(db.String(72), nullable=False)
    
    def __repr__(self):
        return f"<UserAccount(uuid={self.uuid}, username={self.username}, pass={self.hashed_pass})>"
        
class ShareLink(db.Model):
    share_id = db.Column(GUID(), primary_key=True, default=uuid.uuid1)
    item_id = db.Column(GUID(), nullable=False)
    generated_at = db.Column(db.DateTime(), nullable=False)
    expires_at = db.Column(db.DateTime(), nullable=True) # NULL if forever links
    
    def __repr__(self):
        return f"<ShareLink(share_id={self.share_id}, item_id={self.item_id}, generated={self.generated_at}, expires={self.expires_at})>"