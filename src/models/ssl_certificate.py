from dataclasses import dataclass
import pdb
from src.app import db
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def getSubjectAttributeValue(arr):
    if arr is not None:
        if len(arr) > 0 and arr[0] is not None and arr[0].value is not None:
            return arr[0].value
    else:
        return ""

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
    country: str
    state: str
    locality: str
    email: str
    common_name: str
    organization_unit: str
    organization_name: str
    issuer_country: str
    issuer_state: str
    issuer_locality: str
    issuer_email: str
    issuer_common_name: str
    issuer_organization_unit: str
    issuer_organization_name: str
    private_key: str
    certificate_type: str
    
    id = db.Column(db.Integer, primary_key=True)
    
    private_key = db.Column(db.String(10000))
    certificate_type = db.Column(db.String(32))
    
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
    
    #subject attributes
    country = db.Column(db.String(128))
    state = db.Column(db.String(128))
    locality = db.Column(db.String(128))
    email = db.Column(db.String(128))
    common_name = db.Column(db.String(128))
    organization_unit = db.Column(db.String(128))
    organization_name = db.Column(db.String(128))
    
    #issuer attributes
    issuer_country = db.Column(db.String(128))
    issuer_state = db.Column(db.String(128))
    issuer_locality = db.Column(db.String(128))
    issuer_email = db.Column(db.String(128))
    issuer_common_name = db.Column(db.String(128))
    issuer_organization_unit = db.Column(db.String(128))
    issuer_organization_name = db.Column(db.String(128))

    def __init__(self, certificate, created_by, is_csr = False, encrypted_private_key = ""):

        self.certificate = certificate
        self.created_by = created_by
        self.certificate_type = "csr" if is_csr else "certificate"
        
        certificate = x509.load_pem_x509_csr(certificate.encode('utf-8'), default_backend()) if is_csr else x509.load_pem_x509_certificate(certificate.encode(), default_backend())
        subject = certificate.subject
        
        self.private_key = encrypted_private_key
        
        
        self.country = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME))
        self.state = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME))
        self.email = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS))
        self.common_name = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
        self.organization_unit = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))
        self.organization_name = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME))
        self.locality = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME))
        
        if not is_csr:
            issuer = certificate.issuer
            self.issuer_country = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME))
            self.issuer_state = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME))
            self.issuer_email = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS))
            self.issuer_common_name = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
            self.issuer_organization_unit = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))
            self.issuer_organization_name = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME))
            self.issuer_locality = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME))
        
            self.not_valid_after = certificate.not_valid_after.isoformat()
            self.not_valid_before = certificate.not_valid_before.isoformat()
            self.issuer = certificate.issuer.rfc4514_string()
            
            self.version = certificate.version.name
            self.serial_number = certificate.serial_number
            self.signature = certificate.signature
            
        self.signature_hash_algorithm = certificate.signature_hash_algorithm.name
        self.subject = certificate.subject.rfc4514_string()
        
        
        
