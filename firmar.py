import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
import boto3
import time
from dotenv import load_dotenv  

# Cargar variables de entorno desde .env
load_dotenv()

# Configuración de AWS S3
S3_BUCKET_NAME = "bucket-firmadig"  # Nombre de la bucket
S3_KEY_PREFIX = "media/"           # Carpeta en el bucket
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_DEFAULT_REGION")
)

def generar_par_llaves(method="rsa"):
    """Generar el par de llaves pública y privada según el método."""
    if method == "rsa":
        llave_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    elif method == "ecdsa":
        llave_priv = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("Método de firma no soportado.")
    llave_pub = llave_priv.public_key()
    return llave_priv, llave_pub

def hash_archivo(file_key):
    """Crear SHA-512 hash de un archivo desde S3."""
    sha512 = hashlib.sha512()
    try:
        # Descargar el archivo desde S3
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=file_key)
        file_content = response['Body'].read()
        sha512.update(file_content)
    except Exception as e:
        raise Exception(f"Error hashing archivo desde S3: {e}")
    return sha512.digest()

def hash_username(username):
    """Crear SHA-256 hash del nombre de usuario."""
    return hashlib.sha256(username.encode()).hexdigest()

def cargar_llave_priv(llave_priv):
    """Cargar llave privada desde un archivo en S3."""
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=llave_priv)
        llave_priv_data = response['Body'].read()
        llave_priv = serialization.load_pem_private_key(
            llave_priv_data,
            password=None
        )
        return llave_priv
    except Exception as e:
        raise Exception(f"Error cargando llave privada de S3: {e}")

def firmar_documento(file_key, private_key, username, method="rsa"):
    """Firmar documento con la llave privada según el método."""
    file_hash = hash_archivo(file_key)
    if method == "rsa":
        signature = private_key.sign(
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
    elif method == "ecdsa":
        signature = private_key.sign(
            file_hash,
            ec.ECDSA(hashes.SHA512())
        )
    else:
        raise ValueError("Método de firma no soportado.")
    # Incluir hash del username en los metadatos
    username_hash = hash_username(username)
    metadata = f"username_hash:{username_hash}\n".encode()
    return metadata + signature

def guardar_firma(signature, output_key):
    """Guardar la firma en S3."""
    try:
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=output_key, Body=signature)
    except Exception as e:
        raise Exception(f"Error saving signature to S3: {e}")

def sign_document(input_file_key, output_prefix, username, method="rsa"):
    """Firmar un documento generando un nuevo par de claves según el método."""
    timestamp = str(int(time.time()))
    doc_name = os.path.splitext(os.path.basename(input_file_key.split('/')[-1]))[0]
    signature_key = f"{output_prefix}{username}_{doc_name}_{timestamp}.sig"
    key_prefix = f"{output_prefix}keys/"

    try:
        # Generar un nuevo par de claves
        private_key, public_key = generar_par_llaves(method)

        # Firmar el documento
        signature = firmar_documento(input_file_key, private_key, username, method)
        guardar_firma(signature, signature_key)

        # Guardar la clave privada en formato PEM en S3
        private_key_key = f"{key_prefix}{username}_private_key_{method}_{timestamp}.pem"
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=private_key_key, Body=private_key_bytes)

        # Guardar la clave pública en formato PEM en S3
        public_key_key = f"{key_prefix}{username}_public_key_{method}_{timestamp}.pem"
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=public_key_key, Body=public_key_bytes)

        return signature_key, private_key_key, public_key_key, None
    except Exception as e:
        return None, None, None, f"Error al firmar: {str(e)}"
