import qrcode
from PIL import Image
import fitz  # PyMuPDF
import os
import boto3
from dotenv import load_dotenv
from firmar import hash_username

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

def generar_qr(data, output_image):
    """Genera una imagen QR y la guarda"""
    qr = qrcode.make(data).convert("RGB")
    qr.save(output_image)
    return output_image

def encontrar_posicion_sin_texto(pagina, imagen_ancho, imagen_alto, margen=20, paso=5):
    ancho_pagina = pagina.rect.width
    alto_pagina = pagina.rect.height
    bloques = pagina.get_text("blocks")
    zonas_texto = [fitz.Rect(b[:4]) for b in bloques]

    y_inferior = alto_pagina - imagen_alto - margen
    x_inferior = ancho_pagina - imagen_ancho - margen

    for offset in range(0, int(alto_pagina - imagen_alto - 2 * margen), paso):
        y = y_inferior - offset
        rect_qr = fitz.Rect(x_inferior, y, x_inferior + imagen_ancho, y + imagen_alto)
        if not any(rect_qr.intersects(zona) for zona in zonas_texto):
            return rect_qr

    return fitz.Rect(x_inferior, y_inferior, x_inferior + imagen_ancho, y_inferior + imagen_alto)

def insertar_qr_en_pdf(pdf_path, output_pdf_path, username, margen=20, escala=0.4):
    """Inserta un QR con la URL de verificación del usuario en el PDF y guarda el resultado en S3."""
    qr_data = f"https://firma-digital-fehyswytlauyyhd6r2mdkitcmtryn3m.streamlit.app/?verify_secret={hash_username(username)}"
    qr_image_path = "qr_temp.png"
    generar_qr(qr_data, qr_image_path)
    
    doc = fitz.open(pdf_path)
    imagen = Image.open(qr_image_path)

    imagen = imagen.resize(
        (int(imagen.width * escala), int(imagen.height * escala)),
        Image.LANCZOS
    )
    imagen_ancho, imagen_alto = imagen.size

    imagen_reescalada_path = "qr_temp_resized.png"
    imagen.save(imagen_reescalada_path)

    pagina = doc[0]
    rect = encontrar_posicion_sin_texto(pagina, imagen_ancho, imagen_alto, margen)
    pagina.insert_image(rect, filename=imagen_reescalada_path)

    doc.save(output_pdf_path)

    if os.path.exists(qr_image_path):
        os.remove(qr_image_path)
    if os.path.exists(imagen_reescalada_path):
        os.remove(imagen_reescalada_path)

    return output_pdf_path
