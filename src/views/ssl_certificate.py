import os
import re
import subprocess
from flask import make_response, request, jsonify, send_file
from flask_cors import cross_origin
from werkzeug.security import check_password_hash,generate_password_hash
from flask_jwt_extended import create_access_token, current_user, jwt_required, verify_jwt_in_request
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

from src.app import db

from src.models.ssl_certificate import SSLCertificate
import pdb

demoCADirectory = "demoCA/newcerts"

def deleteDemoCAfiles():
    for filename in os.listdir(demoCADirectory):
        file_path = os.path.join(demoCADirectory, filename)
        print(file_path)
        if os.path.isfile(file_path):
            os.remove(file_path)

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

@jwt_required()
@cross_origin()
def sign_csr(csr):
    ca_cert = open('src/rootCA.crt').read()  # Read the root CA certificate from file
    ca_key = open('src/rootCA.key').read()  # Read the root CA private key from file
    ca_password = ''  # Replace with your CA password

    # Write the CSR to a file
    with open('client.csr', 'w') as f:
        f.write(csr)

    # Write the CA certificate to a file
    with open('ca.crt', 'w') as f:
        f.write(ca_cert)

    # Write the CA private key to a file
    with open('ca.key', 'w') as f:
        f.write(ca_key)

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

    with open(cert_file, 'r') as f:
        client_cert = f.read()
    deleteDemoCAfiles()
    return client_cert


@jwt_required()
@cross_origin()
def generate_csr(country, state, locality, organization_name, organization_unit, common_name, email):
    # Build the OpenSSL command to generate the CSR
    openssl_command = [
        'openssl', 'req', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout', 'csr.key',
        '-out', 'csr.csr', '-subj',
        '/C={}/ST={}/L={}/O={}/OU={}/CN={}/emailAddress={}'.format(country, state, locality, organization_name, organization_unit, common_name, email)
    ]

    # Run the OpenSSL command to generate the CSR
    subprocess.run(openssl_command)

    # Read the contents of the CSR file
    with open('csr.csr', 'r') as f:
        csr = f.read()

    # Return the CSR in the response
    return csr

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
        
        generated_csr = generate_csr(
            country=country,
            state=state,
            locality=locality,
            organization_name=organization_name,
            organization_unit=organization_unit,
            common_name=common_name,
            email=email
        )
        
        certificate_string = sign_csr(generated_csr)
        
        if certificate_string:
            cert_match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", certificate_string, re.DOTALL)
            if cert_match:
                cert_str = cert_match.group(0)
                new_cert = SSLCertificate(certificate=cert_str, created_by=user_id)
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
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).all()
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
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).all()
        if certificates is None:
            return jsonify({'data': []}), 200
        else:
            expired_certificates = list(filter(expired_certificates_util, certificates))
            print('expired_certificates',expired_certificates)
            return jsonify({'data': expired_certificates}), 200
        
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500

# Define a cleanup function to delete the certificate file
def cleanup(filename):
    os.remove(filename)

@jwt_required()
@cross_origin()
def download_certificate(user_id, certificate_id):
    try:
        certificate = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).filter(SSLCertificate.id == certificate_id).first()
        if certificate is None:
            return jsonify({'message': 'Certificate not found'}), 200
        else:
            subject_elements = certificate.subject.split(',')
            file_name_start = ''
            for ele_str in subject_elements:
                if ele_str.startswith('CN'):
                    resp = ele_str.split('=')[1]
            
            file_name = f'{file_name_start}.pem'
            # Create an SSL certificate file
            with open(file_name, 'w') as f:
                f.write(certificate.certificate)
            
            # Create a response object
            response = make_response(send_file(file_name, as_attachment=True))

            # # Set the content type and file name
            response.headers.set('Content-Type', 'application/x-pem-file')
            response.headers.set('Content-Disposition', 'attachment', filename='certificate.pem')

            # # Call the cleanup function after the response is sent
            response.call_on_close(file_name)

            # return response
            return response
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500