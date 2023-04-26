import os
import pdb
import re
import subprocess
from flask import request, jsonify
from flask_cors import cross_origin
from flask_jwt_extended import current_user, jwt_required
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from datetime import datetime

from src.app import db

from src.models.ssl_certificate import SSLCertificate
from src.constants import demoCADirectory, encryption_key
fernet = Fernet(encryption_key)

def getSubjectAttributeValue(arr):
    if arr is not None:
        if len(arr) > 0 and arr[0] is not None and arr[0].value is not None:
            return arr[0].value
    else:
        return ""

def deleteDemoCAfiles():
    for filename in os.listdir(demoCADirectory):
        file_path = os.path.join(demoCADirectory, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
            
def writeFileContent(file_path:str, content):
    with open(file_path,"w") as f:
        f.write(content)

def readFileContent(file_path):
    with open(file_path, "r") as f:
        return f.read()

def getEncryptedPrivateKeyFromFile(key_path):
    with open(key_path, "rb") as f:
        key_content = f.read()
    return fernet.encrypt(key_content)

def encryptPrivateKey(private_key):
    return fernet.encrypt(private_key)

def decryptPrivateKey(encrypted_key):
    return fernet.decrypt(encrypted_key)
    

@jwt_required()
def home():
    try:
        return jsonify({
            "message": "Home page",
        }), 200
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while accessing home: {str(e)}'}), 500

@jwt_required()
@cross_origin()
def add_certificate(user_id):
    try:
        certificate = request.json["certificate"]
        new_cert = SSLCertificate(certificate=certificate, created_by=user_id)
        db.session.add(new_cert)
        db.session.commit()
        return jsonify({
            "message": "Certificate added successfully!",
            "certificate": new_cert.id
        }), 201
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while adding certificate: {str(e)}'}), 500


import os
import subprocess

def sign_csr_util(csr):
    ca_cert = open('src/rootCA.crt').read()  # Read the root CA certificate from file
    ca_key = open('src/rootCA.key').read()  # Read the root CA private key from file
    ca_password = ''  # Replace with your CA password


    writeFileContent('client.csr', csr)
    # Write the CSR to a file

    writeFileContent('ca.crt', ca_cert)
    # Write the CA certificate to a file

    writeFileContent('ca.key', ca_key)
    # Write the CA private key to a file

    # Build the OpenSSL command to sign the CSR
    openssl_command = [
        'openssl', 'ca', '-in', 'client.csr', '-out', 'client.crt', '-cert', 'ca.crt', '-keyfile', 'ca.key',
        '-passin', 'pass:{}'.format(ca_password), '-batch'
    ]

    # Run the OpenSSL command to sign the CSR
    try:
        subprocess.run(openssl_command, check=True)
    except subprocess.CalledProcessError as e:
        return None

    # Read the contents of the signed certificate file
    cert_file = os.path.join(os.getcwd(), 'client.crt')
    if not os.path.exists(cert_file):
        return None

    client_cert = readFileContent(cert_file)
    
    deleteDemoCAfiles()
    
    os.remove("client.crt")
    os.remove("ca.crt")
    os.remove("ca.key")
    os.remove("client.csr")
    os.remove("csr.csr")
    return client_cert

@jwt_required()
@cross_origin()
def sign_csr():
    try:
        certificate = request.json["certificate"]
        
        signed_certificate = sign_csr_util(certificate)
        
        if signed_certificate:
            cert_match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", signed_certificate, re.DOTALL)
            if cert_match:
                cert_str = cert_match.group(0)
                new_cert = SSLCertificate(certificate=cert_str, created_by=current_user.id)
                db.session.add(new_cert)
                db.session.commit()
        
            return jsonify({
                "message": "CSR signed successfully!",
                "csr": signed_certificate
            }), 201
        else:
            return jsonify({
                "error":"There was a problem in signing CSR!"
            }), 500

    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while signing CSR: {str(e)}'}), 500



def generate_csr_util(country, state, locality, organization_name, organization_unit, common_name, email):
    # Build the OpenSSL command to generate the CSR
    openssl_command = [
        'openssl', 'req', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout', 'csr.key',
        '-out', 'csr.csr', '-subj',
        '/C={}/ST={}/L={}/O={}/OU={}/CN={}/emailAddress={}'.format(country, state, locality, organization_name, organization_unit, common_name, email)
    ]

    # Run the OpenSSL command to generate the CSR
    subprocess.run(openssl_command)

    encrypted_private_key = getEncryptedPrivateKeyFromFile('csr.key')

    # Save the encrypted file to disk
    # with open(f'keys/{common_name}_{email}.enc', 'wb') as f:
    #     f.write(encrypted_private_key)
        
    # Read the contents of the CSR file
    with open('csr.csr', 'r') as f:
        csr = f.read()
        
    # Return the CSR in the response
    return csr, encrypted_private_key

@jwt_required()
@cross_origin()
def generate_csr():
    try:
        certificate = request.json["certificate"]
        name = certificate['name']
        country = certificate['country']
        state = certificate["state"]
        email = certificate["email"]
        common_name = certificate["common_name"]
        organization_unit = certificate["organization_unit"]
        organization_name = certificate["organization_name"]
        locality = certificate["locality"]
        generated_csr, encrypted_private_key = generate_csr_util(
            country=country,
            state=state,
            locality=locality,
            organization_name=organization_name,
            organization_unit=organization_unit,
            common_name=common_name,
            email=email
        )
        
        if generated_csr:
                csr = SSLCertificate(certificate=generated_csr, created_by=current_user.id, is_csr=True)
                db.session.add(csr)
                db.session.commit()
                return jsonify({
                    "message": "CSR created successfully!",
                    "csr": generated_csr
                }), 201
        else:
            return jsonify({
                "error":"There was a problem in generating CSR!"
            }), 500

    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while generating CSR: {str(e)}'}), 500

@jwt_required()
@cross_origin()
def create_certificate(user_id):
    try:
        certificate = request.json["certificate"]
        name = certificate['name']
        country = certificate['country']
        state = certificate["state"]
        email = certificate["email"]
        common_name = certificate["common_name"]
        organization_unit = certificate["organization_unit"]
        organization_name = certificate["organization_name"]
        locality = certificate["locality"]
        generated_csr, encrypted_private_key = generate_csr_util(
            country=country,
            state=state,
            locality=locality,
            organization_name=organization_name,
            organization_unit=organization_unit,
            common_name=common_name,
            email=email
        )
        
        certificate_string = sign_csr_util(generated_csr)
        
        if certificate_string:
            cert_match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", certificate_string, re.DOTALL)
            if cert_match:
                cert_str = cert_match.group(0)
                new_cert = SSLCertificate(certificate=cert_str, created_by=user_id, encrypted_private_key=encrypted_private_key)
                db.session.add(new_cert)
                db.session.commit()
                return jsonify({
                    "message": "Certificate created successfully!",
                    "certificate": new_cert.id
                }), 201
            else:
                return jsonify({
                    "error":"There was a problem in signing certificate!"
                })

        else:
            return jsonify({
                "error":"There was a problem signing csr!"
            }), 500
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while adding certificate: {str(e)}'}), 500

@cross_origin()
def get_certificate(user_id, certificate_id):
    try:
        cert = SSLCertificate.query.filter(SSLCertificate.id == certificate_id, SSLCertificate.created_by == user_id).first()
        if cert is None:
            return 'Certificate not found', 404
        else:
            if cert.created_by == user_id:
                certificate = x509.load_pem_x509_certificate(cert.certificate.encode(), default_backend())
                expiry_date = certificate.not_valid_after
                return jsonify({'start_date': certificate.not_valid_before, 'expiry_date': expiry_date, "certificate":cert}), 200
            else:
                return 'This certificate is owned by someone else!'
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500

@jwt_required()
@cross_origin()
def get_certificates(user_id):
    try:
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).all()
        if certificates is None:
            return 'No certificates created.', 404
        else:
            return jsonify({'data': certificates}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500
    
def near_expiry_certificate_util(certificate):
    cert_nva = datetime.fromisoformat(certificate.not_valid_after)
    now = datetime.now()
    diff_days = cert_nva - now
    if (-1 < diff_days.days < 5):
        return True
    else:
        return False

@jwt_required()
@cross_origin()
def get_near_expiry_certificates(user_id):
    try:
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id, SSLCertificate.certificate_type != 'csr').all()
        if certificates is None:
            return 'No certificates created.', 404
        else:
            near_expiry_certificates = list(filter(near_expiry_certificate_util, certificates))
            return jsonify({'data': near_expiry_certificates}), 200
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500

def expired_certificates_util(certificate):
    cert_nva = datetime.fromisoformat(certificate.not_valid_after)
    now = datetime.now()
    diff_days = cert_nva - now;
    if (diff_days.total_seconds() < 0):
        return True
    else:
        return False

@jwt_required()
@cross_origin()
def get_expired_certificates(user_id):
    try:
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id, SSLCertificate.certificate_type != 'csr').all()
        if certificates is None:
            return jsonify({'data': []}), 200
        else:
            expired_certificates = list(filter(expired_certificates_util, certificates))
            return jsonify({'data': expired_certificates}), 200
        
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500

# Define a cleanup function to delete the certificate file
def cleanup(filename):
    os.remove(f'src/{filename}')

@jwt_required()
@cross_origin()
def download_certificate(user_id, certificate_id):
    try:
        certificate = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).filter(SSLCertificate.id == certificate_id).first()
        if certificate is None:
            return jsonify({'message': 'Certificate not found'}), 500
        else:
            subject_elements = certificate.subject.split(',')
            file_name_start = ''
            for ele_str in subject_elements:
                if ele_str.startswith('CN'):
                    file_name_start = ele_str.split('=')[1]
            
            file_name = f'{file_name_start}.pem'
    
            return jsonify({
                "file": certificate.certificate,
                "file_name": file_name
            }), 200
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': 'Failed to download certificate'}), 500

@jwt_required()
@cross_origin()
def renew_certificate(user_id,certificate_id):
    try:
        certificate = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).filter(SSLCertificate.id == certificate_id).first()
        if not certificate:
            return jsonify({
                "error": f"Certificate with ID {certificate_id} not found."
            }), 404
        
        indexFile = open("demoCA/index.txt", "w")
        oldIndexFile = open("demoCA/index.txt.old","w")
        indexFile.close()
        oldIndexFile.close()
        loadedCertificate = x509.load_pem_x509_certificate(certificate.certificate.encode(), default_backend())
        subject = loadedCertificate.subject
        country = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME))
        state = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME))
        email = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS))
        common_name = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
        organization_unit = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))
        organization_name = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME))
        locality = getSubjectAttributeValue(subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME))
        
        generated_csr, encrypted_private_key = generate_csr_util(
            country=country,
            state=state,
            locality=locality,
            organization_name=organization_name,
            organization_unit=organization_unit,
            common_name=common_name,
            email=email
        )
        certificate_string = sign_csr_util(generated_csr)
        
        if certificate_string:
            cert_match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", certificate_string, re.DOTALL)
            if cert_match:
                cert_str = cert_match.group(0)
                db.session.delete(certificate)
                renewed_cert = SSLCertificate(certificate=cert_str, created_by=user_id, encrypted_private_key=encrypted_private_key)
                db.session.add(renewed_cert)
                db.session.commit()
                return jsonify({
                    "message": "Certificate renewed successfully!",
                    "certificate": certificate.id
                }), 200
            else:
                return jsonify({
                    "error": "There was a problem in signing certificate!"
                })
        else:
            return jsonify({
                "error": "There was a problem signing csr!"
            }), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "error": f"An error occurred while renewing certificate: {str(e)}"
        }), 500