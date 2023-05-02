from dataclasses import dataclass
from src.app import db
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def getSubjectAttributeValue(arr):
    if arr is not None:
        if len(arr) > 0 and arr[0] is not None and arr[0].value is not None:
            return arr[0].value
    else:
        return ""

def generateSslCertUtil(self, certificate:str, is_csr=False):
    self.certificate = certificate
    
    certificate_type = "csr" if is_csr else "certificate"
    self.certificate_type = certificate_type
    
    certificate = x509.load_pem_x509_csr(certificate.encode('utf-8'), default_backend()) if is_csr else x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    subject = certificate.subject
    
    country = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME))
    state = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME))
    email = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS))
    common_name = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
    organization_unit = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))
    organization_name = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME))
    locality = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME))
    
    self.country = country
    self.state = state
    self.email = email
    self.common_name = common_name
    self.organization_unit =  organization_unit
    self.organization_name =  organization_name
    self.locality =  locality
    
    if not is_csr:
        issuer = certificate.issuer
        issuer_country = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME))
        issuer_state = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME))
        issuer_email = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS))
        issuer_common_name = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
        issuer_organization_unit = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))
        issuer_organization_name = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME))
        issuer_locality = getSubjectAttributeValue(issuer.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME))
    
        self.issuer_country = issuer_country
        self.issuer_state = issuer_state
        self.issuer_email = issuer_email
        self.issuer_common_name = issuer_common_name
        self.issuer_organization_unit = issuer_organization_unit
        self.issuer_organization_name = issuer_organization_name
        self.issuer_locality = issuer_locality

        not_valid_after = certificate.not_valid_after.isoformat()
        not_valid_before = certificate.not_valid_before.isoformat()
        issuer = certificate.issuer.rfc4514_string()
        
        self.not_valid_after = not_valid_after
        self.not_valid_before = not_valid_before
        self.issuer = issuer
        
        version = certificate.version.name
        serial_number = certificate.serial_number
        signature = certificate.signature
        
        self.version = version
        self.serial_number = serial_number
        self.signature = signature
        
    signature_hash_algorithm = certificate.signature_hash_algorithm.name
    subject = certificate.subject.rfc4514_string()
        
    self.signature_hash_algorithm = signature_hash_algorithm
    self.subject = subject
        
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
        self.created_by = created_by
        self.private_key = encrypted_private_key
        generateSslCertUtil(self, certificate=certificate, is_csr=is_csr)
        
    def update_certificate(self, certificate):
        generateSslCertUtil(self=self, certificate=certificate)
        
