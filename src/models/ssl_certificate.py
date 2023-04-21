from dataclasses import dataclass
from src.app import db
from cryptography import x509
from cryptography.hazmat.backends import default_backend

@dataclass
class SSLCertificate(db.Model):
    __tablename__ = 'sslcertificate'
    id: int
    certificate: str
    created_by: int
    not_valid_after: str
    not_valid_before: str
    issuer: str
    serial_number: str
    signature: str
    signature_hash_algorithm: str
    subject: str
    version: str
    name: str
    
    id = db.Column(db.Integer, primary_key=True)
    certificate = db.Column(db.String(10000))
    created_by = db.Column(db.Integer)
    not_valid_after = db.Column(db.String(64))
    not_valid_before = db.Column(db.String(64))
    issuer = db.Column(db.String(256))
    serial_number = db.Column(db.String(256))
    signature = db.Column(db.String(10000))
    signature_hash_algorithm = db.Column(db.String(256))
    subject = db.Column(db.String(10000))
    version = db.Column(db.String(256))
    name = db.Column(db.String(128))

    def __init__(self, certificate, created_by):
        self.certificate = certificate
        certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
        self.created_by = created_by
        self.not_valid_after = certificate.not_valid_after.isoformat()
        self.not_valid_before = certificate.not_valid_before.isoformat()
        self.issuer = certificate.issuer.rfc4514_string()
        self.serial_number = certificate.serial_number
        self.signature = certificate.signature
        self.signature_hash_algorithm = certificate.signature_hash_algorithm.name
        self.subject = certificate.subject.rfc4514_string()
        self.version = certificate.version.name
        
        
