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
S3_BUCKET_NAME = "bucket-firmadig"
S3_KEY_PREFIX = "media/"
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

def find_signature_key(document_key, username):
    """Buscar el archivo de firma en S3 basado en el documento y el usuario."""
    doc_name = os.path.splitext(os.path.basename(document_key))[0]
    user_prefix = f"{S3_KEY_PREFIX}{username}/documents/"
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=user_prefix)
        sig_files = [
            obj['Key'] for obj in response.get('Contents', [])
            if obj['Key'].endswith('.sig') and f"{username}_{doc_name}_" in obj['Key']
        ]
        if not sig_files:
            raise Exception("No se encontró un archivo de firma para el documento y usuario.")
        # Seleccionar el archivo de firma más reciente (basado en timestamp)
        return max(sig_files, key=lambda x: int(x.split('_')[-1].replace('.sig', '')))
    except Exception as e:
        raise Exception(f"Error buscando archivo de firma en S3: {e}")

def load_public_key(username, method):
    """Cargar llave pública desde S3 basada en el usuario y método."""
    key_path = f"{S3_KEY_PREFIX}{username}/keys/{username}_{method}_public_key.pem"
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=key_path)
        public_key_data = response['Body'].read()
        public_key = serialization.load_pem_public_key(public_key_data)
        return public_key
    except Exception as e:
        raise Exception(f"Error loading public key from S3 for {username}: {e}")

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

def verify_document(document_key, username):
    """Verificar un documento con su firma y la clave pública del usuario desde S3."""
    try:
        # Buscar el archivo de firma
        signature_key = find_signature_key(document_key, username)
        signature, _ = cargar_firma(signature_key)
        
        # Intentar verificar con RSA
        public_key_rsa = load_public_key(username, "rsa")
        if verificar_firma_rsa(document_key, signature, public_key_rsa):
            return True, "Verificación de firma exitosa con RSA. El documento es auténtico."
        
        # Intentar verificar con ECDSA
        public_key_ecdsa = load_public_key(username, "ecdsa")
        if verificar_firma_ecdsa(document_key, signature, public_key_ecdsa):
            return True, "Verificación de firma exitosa con ECDSA. El documento es auténtico."
        
        # Si ambos métodos fallan
        return False, "Verificación de firma fallida. El documento no corresponde o fue manipulado."
    except Exception as e:
        return False, f"Error al verificar: {str(e)}"
