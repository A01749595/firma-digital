import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import boto3
import os
from dotenv import load_dotenv  

# Cargar variables de entorno desde .env
load_dotenv()

# Configuración de AWS S3
S3_BUCKET_NAME = "bucket-efirma"  # Nombre del bucket
S3_KEY_PREFIX = "media/"        # Carpeta en el bucket
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_DEFAULT_REGION")
)

def hash_archivo(file_key):
    """Crear SHA-512 hash de un archivo desde S3."""
    sha512 = hashlib.sha512()
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=file_key)
        file_content = response['Body'].read()
        sha512.update(file_content)
    except Exception as e:
        raise Exception(f"Error hashing archivo desde S3: {e}")
    return sha512.digest()

def hash_username(username):
    """Crear SHA-256 hash del nombre de usuario."""
    return hashlib.sha256(username.encode()).hexdigest()

def cargar_firma(signature_key):
    """Cargar firma desde un archivo en S3, separando metadatos."""
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=signature_key)
        data = response['Body'].read()
        metadata, signature = data.split(b"\n", 1)
        metadata = metadata.decode()
        username_hash = metadata.split("username_hash:")[1]
        return signature, username_hash
    except Exception as e:
        raise Exception(f"Error cargando firma desde S3: {e}")

def load_public_key(public_path):
    """Cargar llaves públicas desde S3."""
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=public_path)
        public_key_data = response['Body'].read()
        public_key = serialization.load_pem_public_key(public_key_data)
        return public_key
    except Exception as e:
        raise Exception(f"Error loading public key from S3: {e}")

def verificar_firma_rsa(file_key, signature, public_key):
    """Verificar la firma del documento con la clave pública RSA."""
    file_hash = hash_archivo(file_key)
    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return True
    except InvalidSignature:
        return False

def verificar_firma_ecdsa(file_key, signature, public_key):
    """Verificar la firma del documento con la clave pública ECDSA."""
    file_hash = hash_archivo(file_key)
    try:
        public_key.verify(
            signature,
            file_hash,
            ec.ECDSA(hashes.SHA512())
        )
        return True
    except InvalidSignature:
        return False

def verify_document(document_key, signature_key, public_key_path):
    """Verificar un documento con su firma y clave pública desde S3."""
    try:
        public_key = load_public_key(public_key_path)
        signature, _ = cargar_firma(signature_key)
        
        # Determinar el tipo de clave pública y usar el método de verificación adecuado
        if isinstance(public_key, rsa.RSAPublicKey):
            if verificar_firma_rsa(document_key, signature, public_key):
                return True, "Verificación de firma exitosa. El documento es auténtico."
            else:
                return False, "Verificación de firma fallida. El documento no corresponde o fue manipulado."
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if verificar_firma_ecdsa(document_key, signature, public_key):
                return True, "Verificación de firma exitosa. El documento es auténtico."
            else:
                return False, "Verificación de firma fallida. El documento no corresponde o fue manipulado."
        else:
            return False, "Tipo de clave pública no soportado."
    except Exception as e:
        return False, f"Error al verificar: {str(e)}"