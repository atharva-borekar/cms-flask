from cryptography.fernet import Fernet

demoCADirectory = "demoCA/newcerts"

encryption_key = Fernet.generate_key()