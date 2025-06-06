import streamlit as st
import pandas as pd
import os
from pathlib import Path
import hashlib
from datetime import datetime
import zipfile
import io
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
import time
from cryptography.exceptions import InvalidSignature
import qrcode
import time
from PIL import Image
import fitz  # PyMuPDF
import base64
import requests
import boto3  # Added for AWS S3 integration
from dotenv import load_dotenv  # Added for loading .env file

# Cargar variables de entorno desde .env
load_dotenv()

# Configuración inicial de la página 
st.set_page_config(page_title="App de Firma Digital", layout="centered")

# Código de verificación para administradores 
ADMIN_SECRET_CODE = os.getenv("ADMIN_SECRET_CODE")  

# Configuración de AWS S3
S3_BUCKET_NAME = "bucket-firmadig"  # Reemplaza con el nombre de tu bucket
S3_KEY_PREFIX = "media/"
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_DEFAULT_REGION")
)

# GitHub Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Add your GitHub Personal Access Token to .env
GITHUB_REPO = "A01749595/firma-digital"  # Replace with your GitHub username and repo name
GITHUB_BRANCH = "main"  # Replace with your branch name
GITHUB_FILE_PATH = "usuarios.csv"  # Path to usuarios.csv in the repository

# Path to usuarios.csv in S3
USERS_FILE_S3_KEY = "app_data/usuarios.csv"


# Function to update usuarios.csv in GitHub repository
def update_users_csv_in_github():
    try:
        # Download the updated usuarios.csv from S3
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=USERS_FILE_S3_KEY)
        csv_content = response['Body'].read()

        # Base64 encode the content
        content_base64 = base64.b64encode(csv_content).decode('utf-8')

        # Get the current file from GitHub to obtain its SHA (required for updates)
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}?ref={GITHUB_BRANCH}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        file_info = response.json()
        current_sha = file_info['sha']

        # Update the file on GitHub
        update_url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        payload = {
            "message": f"Update usuarios.csv with new user registration at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": content_base64,
            "sha": current_sha,
            "branch": GITHUB_BRANCH
        }
        response = requests.put(update_url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except Exception as e:
        st.error(f"Error updating usuarios.csv in GitHub: {e}")
        return False

# Configuration
USER_FILE = "usuarios.csv"

# ------ App -----

# Definir el CSS para el fondo, tipografía e imágenes
style = """
    <style>
        /* Importar fuente de Google Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Helvetica:wght@300;400;700&display=swap');
        
        /* Fondo de la página */
        [data-testid="stAppViewContainer"] {
            background: linear-gradient(to top, #06132f, #4e85f8) !important;
        }
        /* Estilos generales */
        body {
            background-color: #06132f !important;
            color: white !important;
            font-family: 'Helvetica', sans-serif !important;
        }
        /* Estilos para texto */
        h1, h2, h3, h4, h5, h6, p, div, .stMarkdown, .stText {
            color: white !important;
            font-family: 'Helvetica', sans-serif !important;
        }
        /* Ajustar widgets para mejor visibilidad */
        .stButton > button {
            background-color: #030712 !important;
            color: white !important;
            font-family: 'Helvetica', sans-serif !important;
            border-radius: 5px;
            padding: 8px 16px;
        }
        /* Estilo específico para el language_button */
        button[kind="secondary"] {
            background-color: #151515 !important;
            color: white !important;
            font-family: 'Helvetica', sans-serif !important;
            border-radius: 5px;
            padding: 8px 16px;
        }
        .stTextInput > div > div > input {
            background-color: #264ab2;
            color: white;
            font-family: 'Helvetica', sans-serif;
        }
        .stFileUploader > div > button {
            background-color: #1e3a8a;
            color: white;
            font-family: 'Helvetica', sans-serif;
        }
        /* Estilo para pestañas */
        .stTabs > div > button {
            font-family: 'Helvetica', sans-serif;
            color: white;
        }
        /* Posicionar imágenes en las esquinas */
        .logo-left img {
            position: fixed;
            top: 10px;
            left: 10px;
            width: 250px;
            z-index: 1000;
        }
        .logo-right img {
            position: fixed;
            top: 10px;
            right: 10px;
            width: 190px;
            z-index: 1000;
        }
        /* Agregar margen superior al contenido principal */
        .stApp > div:first-child {
            margin-top: 150px;
        }
        /* Estilo específico para el título */
        h1 {
            font-size: 32px !important;
            text-align: center;
            margin-bottom: 20px;
            font-family: 'Helvetica', sans-serif !important;
        }
        /* Estilo para el texto al final (footer) */
        .footer-text {
            color: white !important;
            font-family: 'Helvetica', sans-serif !important;
            text-align: center;
            margin-top: 50px;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
"""

# Inyectar el CSS
st.markdown(style, unsafe_allow_html=True)

# Configuration
USER_FILE = "usuarios.csv"

# Diccionario para traducción
TRANSLATIONS = {
    "es": {
        "page_title": "App de Firma Digital",
        "welcome_title": "Bienvenido a la App de Firma Digital",
        "select_role_tab": "Seleccionar Rol",
        "login_tab": "Iniciar Sesión",
        "register_tab": "Registrarse",
        "login_header": "Iniciar Sesión",
        "username": "Nombre de usuario",
        "password": "Contraseña",
        "login_button": "Iniciar Sesión",
        "login_success": "¡Inicio de sesión exitoso!",
        "login_error": "Nombre de usuario o contraseña inválidos",
        "register_header": "Registrarse",
        "new_username": "Nuevo Nombre de usuario",
        "new_password": "Nueva Contraseña",
        "role_label": "Selecciona tu rol",
        "role_admin": "Administrador",
        "role_user": "Alumno",
        "admin_code_label": "Código de verificación de administrador",
        "admin_code_error": "Código de administrador incorrecto",
        "register_button": "Registrarse",
        "register_success": "¡Registro exitoso! Por favor, inicia sesión.",
        "register_error_exists": "Nombre de usuario ya existe",
        "register_error_empty": "Por favor, completa todos los campos",
        "welcome": "¡Bienvenido, {username}!",
        "dashboard": "Este es tu panel de firma digital.",
        "logout": "Cerrar Sesión",
        "sign_tab": "Firmar Documento",
        "qr_tab": "Generar QR",
        "verify_tab": "Verificar Documento",
        "files_tab": "Mis Archivos",
        "download_files_tab": "Descargar Archivos de Alumnos",
        "sign_header": "Firmar Documento",
        "upload_sign": "Subir documento para firmar (PDF)",
        "upload_pdf_for_qr": "Subir PDF para agregar QR",
        "generate_qr_button": "Generar PDF con QR",
        "download_pdf_with_qr": "Descargar PDF con QR",
        "qr_generation_success": "¡PDF con QR generado exitosamente!",
        "document_uploaded": "Documento subido: {filename}",
        "sign_button": "Firmar Documento",
        "sign_with_rsa": "Firmar con RSA",
        "sign_with_ecdsa": "Firmar con ECDSA",
        "sign_success": "¡Documento firmado exitosamente!",
        "sign_error": "Error al firmar: {error}",
        "signature_caption": "Firma digital generada",
        "verify_header": "Verificar Documento",
        "upload_verify": "Subir documento para verificar (PDF)",
        "upload_signature": "Subir archivo de firma (.sig)",
        "upload_public_key": "Subir clave pública (.pem)",
        "verify_button": "Verificar Documento",
        "verify_success": "¡Documento verificado exitosamente!",
        "verify_error": "Error al verificar: {error}",
        "verify_details": "Detalles de verificación:",
        "verified_on": "Verificado el: {timestamp}",
        "verify_caption": "Verificación completada",
        "language_button": "Cambiar a Inglés",
        "download_zip": "Descargar ZIP (Firma y Claves)",
        "back_button": "Regresar",
        "are_you_admin_button": "Eres Administrador?",
        "select_user": "Seleccionar usuario",
        "download_user_files": "Descargar archivos del usuario",
        "no_files": "No hay archivos disponibles para descargar."
    },
    "en": {
        "page_title": "Digital Signature App",
        "welcome_title": "Welcome to the Digital Signature App",
        "select_role_tab": "Select Role",
        "login_tab": "Login",
        "register_tab": "Register",
        "login_header": "Login",
        "username": "Username",
        "password": "Password",
        "login_button": "Login",
        "login_success": "Login successful!",
        "login_error": "Invalid username or password",
        "register_header": "Register",
        "new_username": "New Username",
        "new_password": "New Password",
        "role_label": "Select your role",
        "role_admin": "Administrator",
        "role_user": "Student",
        "admin_code_label": "Administrator verification code",
        "admin_code_error": "Incorrect administrator code",
        "register_button": "Register",
        "register_success": "Registration successful! Please login.",
        "register_error_exists": "Username already exists",
        "register_error_empty": "Please fill in all fields",
        "welcome": "Welcome, {username}!",
        "dashboard": "This is your digital signature dashboard.",
        "logout": "Logout",
        "sign_tab": "Sign Document",
        "qr_tab": "Generate QR",
        "verify_tab": "Verify Document",
        "files_tab": "My Files",
        "download_files_tab": "Download Student Files",
        "sign_header": "Sign Document",
        "upload_sign": "Upload document to sign (PDF)",
        "upload_pdf_for_qr": "Upload PDF to add QR",
        "generate_qr_button": "Generate PDF with QR",
        "download_pdf_with_qr": "Download PDF with QR",
        "qr_generation_success": "PDF with QR generated successfully!",
        "document_uploaded": "Document uploaded: {filename}",
        "sign_button": "Sign Document",
        "sign_with_rsa": "Sign with RSA",
        "sign_with_ecdsa": "Sign with ECDSA",
        "sign_success": "Document signed successfully!",
        "sign_error": "Error signing: {error}",
        "signature_caption": "Digital signature generated",
        "verify_header": "Verify Document",
        "upload_verify": "Upload document to verify (PDF)",
        "upload_signature": "Upload signature file (.sig)",
        "upload_public_key": "Upload public key (.pem)",
        "verify_button": "Verify Document",
        "verify_success": "Document verified successfully!",
        "verify_error": "Error verifying: {error}",
        "verify_details": "Verification details:",
        "verified_on": "Verified on: {timestamp}",
        "verify_caption": "Verification completed",
        "language_button": "Switch to Spanish",
        "download_zip": "Download ZIP (Signature and Keys)",
        "back_button": "Back",
        "are_you_admin_button": "Are you an Administrator?",
        "select_user": "Select user",
        "download_user_files": "Download user files",
        "no_files": "No files available for download."
    }
}

# Función para traducir el texto
def t(key, **kwargs):
    text = TRANSLATIONS[st.session_state.get("language", "es")][key]
    return text.format(**kwargs) if kwargs else text

# Función para obtener/extraer contraseñas
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Función para inicializar la base de datos de usuarios
def init_user_db():
    try:
        if not os.path.exists(USER_FILE):
            df = pd.DataFrame(columns=["username", "password", "role"])
            df.to_csv(USER_FILE, index=False)
    except OSError as e:
        st.error(f"Error creating user database: {e}")
        raise

# Función para registrar a un nuevo usuario
def register_user(username, password, role):
    try:
        df = pd.read_csv(USER_FILE)
        if username in df["username"].values:
            return False, "register_error_exists"
        hashed_password = hash_password(password)
        new_user = pd.DataFrame([[username, hashed_password, role]], columns=["username", "password", "role"])
        df = pd.concat([df, new_user], ignore_index=True)
        df.to_csv(USER_FILE, index=False)

        # Crear el "directorio" del usuario en S3 (usando un prefijo)
        user_prefix = f"{S3_KEY_PREFIX}{username}/documents/"
        try:
            # S3 no requiere crear "carpetas" explícitamente, pero podemos crear un objeto vacío para simularlo
            s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=user_prefix)
        except Exception as e:
            st.error(f"Error creating S3 prefix for {username}: {e}")
            return True, "register_success"

        return True, "register_success"
    except OSError as e:
        st.error(f"Error registering user: {e}")
        return False, "register_error"

# Función para verificar las credenciales de inicio de sesión y obtener el rol
def verify_user(username, password):
    try:
        df = pd.read_csv(USER_FILE)
        hashed_password = hash_password(password)
        user_row = df[(df["username"] == username) & (df["password"] == hashed_password)]
        if not user_row.empty:
            return True, user_row["role"].iloc[0]
        return False, None
    except OSError as e:
        st.error(f"Error verifying user: {e}")
        return False, None

# Función para crear un archivo ZIP desde S3
def create_zip_file_from_s3(s3_files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for s3_file in s3_files:
            file_name = s3_file.split('/')[-1]
            try:
                response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=s3_file)
                file_content = response['Body'].read()
                zip_file.writestr(file_name, file_content)
            except Exception as e:
                st.error(f"Error adding {file_name} to ZIP: {e}")
    buffer.seek(0)
    return buffer.getvalue()

# Inicializar el estado de la sesión
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = None
    st.session_state.selected_role = None
if "language" not in st.session_state:
    st.session_state.language = "es"
if "signed_files" not in st.session_state:
    st.session_state.signed_files = None  # Store paths of signed files
if "signing_method" not in st.session_state:
    st.session_state.signing_method = None  # Track signing method (rsa or ecdsa)

# Inicializar la base de datos de usuarios
init_user_db()

# Muestra los logos a los lados (Tec y Prepanet) with error handling
col1, col2, col3 = st.columns([5, 2, 5])
with col1:
        st.image("assets/tec de monterrey.png", width=250)
with col3:
        st.image("assets/PREPANET.png", width=190)

# Botón de cambio de idioma
if st.button(t("language_button")):
    st.session_state.language = "en" if st.session_state.language == "es" else "es"
    st.rerun()

# Agregar título
st.title(t("welcome_title"))

if not st.session_state.logged_in:
    # Controlar si se muestran las pestañas de administrador o usuario
    if "show_admin_tabs" not in st.session_state:
        st.session_state.show_admin_tabs = False

    if not st.session_state.show_admin_tabs:
        # Pestañas para usuario por defecto
        tabs = st.tabs([t("login_tab"), t("register_tab")])
        
        with tabs[0]:  # Pestaña Iniciar Sesión (Alumno)
            st.header(t("login_header"))
            with st.form("login_form_user"):
                username = st.text_input(t("username"), key="user_login_username")
                password = st.text_input(t("password"), type="password", key="user_login_password")
                login_button = st.form_submit_button(t("login_button"))
                
                if login_button:
                    is_valid, role = verify_user(username, password)
                    if is_valid:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.role = role
                        st.session_state.show_admin_tabs = False
                        st.success(t("login_success"))
                        st.rerun()
                    else:
                        st.error(t("login_error"))
            
        
        with tabs[1]:  # Pestaña Registrarse (Alumno)
            st.header(t("register_header"))
            with st.form("register_form_user"):
                new_username = st.text_input(t("new_username"), key="user_register_username")
                new_password = st.text_input(t("new_password"), type="password", key="user_register_password")
                register_button = st.form_submit_button(t("register_button"))
                
                if register_button:
                    if new_username and new_password:
                        role_value = "student"
                        success, message = register_user(new_username, new_password, role_value)
                        if success:
                            st.success(t("register_success"))
                            time.sleep(2)  # Delay to show success message
                            st.session_state.show_admin_tabs = False
                            st.rerun()
                        else:
                            st.error(t(message))
                    else:
                        st.error(t("register_error_empty"))
            if st.button(t("are_you_admin_button"), key="to_admin_register"):
                st.session_state.show_admin_tabs = True
                st.rerun()
    else:
        # Pestañas para administrador
        tabs = st.tabs([t("login_tab"), t("register_tab")])
        
        with tabs[0]:  # Pestaña Iniciar Sesión (Administrador)
            st.header(t("login_header"))
            if st.button(t("back_button"), key="back_login_admin"):
                st.session_state.show_admin_tabs = False
                st.rerun()
            with st.form("login_form_admin"):
                username = st.text_input(t("username"), key="admin_login_username")
                password = st.text_input(t("password"), type="password", key="admin_login_password")
                login_button = st.form_submit_button(t("login_button"))
                
                if login_button:
                    is_valid, role = verify_user(username, password)
                    if is_valid:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.role = role
                        st.session_state.show_admin_tabs = False
                        st.success(t("login_success"))
                        st.rerun()
                    else:
                        st.error(t("login_error"))
        
        with tabs[1]:  # Pestaña Registrarse (Administrador)
            st.header(t("register_header"))
            if st.button(t("back_button"), key="back_register_admin"):
                st.session_state.show_admin_tabs = False
                st.rerun()
            with st.form("register_form_admin"):
                new_username = st.text_input(t("new_username"), key="admin_register_username")
                new_password = st.text_input(t("new_password"), type="password", key="admin_register_password")
                admin_code = st.text_input(t("admin_code_label"), type="password")
                register_button = st.form_submit_button(t("register_button"))
                
                if register_button:
                    if new_username and new_password:
                        role_value = "admin"
                        if admin_code != ADMIN_SECRET_CODE:
                            st.error(t("admin_code_error"))
                        else:
                            success, message = register_user(new_username, new_password, role_value)
                            if success:
                                st.success(t("register_success"))
                                time.sleep(2)  # Delay to show success message
                                st.session_state.show_admin_tabs = False
                                st.rerun()
                            else:
                                st.error(t(message))
                    else:
                        st.error(t("register_error_empty"))
else:
    # Mensaje de Bienvenida
    role_display = t("role_admin") if st.session_state.role == "admin" else t("role_user")
    st.title(t("welcome", username=st.session_state.username, role=role_display))
    st.write(t("dashboard"))
    
    # Botón de cerrar sesión
    if st.button(t("logout")):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.role = None
        st.session_state.signed_files = None
        st.session_state.signing_method = None
        st.rerun()
    
    # Mostrar pestañas según el rol
    if st.session_state.role == "admin":
        tabs = st.tabs([t("sign_tab"), t("qr_tab"), t("verify_tab"), t("download_files_tab")])
        
        with tabs[0]:  # Pestaña Firmar Documento
            st.header(t("sign_header"))
            uploaded_file = st.file_uploader(t("upload_sign"), type=["pdf"], key="sign_uploader")
            if uploaded_file:
                st.write(t("document_uploaded", filename=uploaded_file.name))
                
                # Botones para elegir método de firma
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(t("sign_with_rsa")):
                        st.session_state.signing_method = "rsa"
                with col2:
                    if st.button(t("sign_with_ecdsa")):
                        st.session_state.signing_method = "ecdsa"

                # Mostrar el formulario de firma solo si se ha seleccionado un método
                if st.session_state.signing_method:
                    with st.form("sign_form"):
                        # Seleccionar el usuario "alumno" para firmar su documento
                        df = pd.read_csv(USER_FILE)
                        alumnos = df[df["role"] == "student"]["username"].tolist()
                        target_user = st.selectbox(t("select_user"), alumnos)
                        sign_button = st.form_submit_button(t("sign_button"))
                        
                        if sign_button:
                            # Guardar archivo subido en S3
                            user_prefix = f"{S3_KEY_PREFIX}{target_user}/documents/"
                            doc_key = f"{user_prefix}{uploaded_file.name}"
                            try:
                                s3_client.upload_fileobj(uploaded_file, S3_BUCKET_NAME, doc_key)
                            except Exception as e:
                                st.error(f"Error uploading document to S3: {e}")
                                st.stop()
                            
                            # Firmar documento según el método seleccionado
                            signature_key, private_key_key, public_key_key, error = sign_document(
                                doc_key, user_prefix, target_user, method=st.session_state.signing_method
                            )
                            
                            if error:
                                st.error(t("sign_error", error=error))
                            else:
                                st.success(t("sign_success"))
                                st.write(t("signature_caption"))
                                # Almacenar claves en S3 en session_state
                                st.session_state.signed_files = {
                                    "signature": signature_key,
                                    "public_key": public_key_key,
                                    "private_key": private_key_key
                                }
                                # Crear el archivo ZIP desde S3
                                try:
                                    zip_content = create_zip_file_from_s3([
                                        signature_key,
                                        public_key_key,
                                        private_key_key
                                    ])
                                    st.session_state.zip_file = zip_content
                                except Exception as e:
                                    st.error(f"Error creating ZIP file: {e}")
                                    st.session_state.zip_file = None
                                # Resetear el método de firma después de un éxito
                                st.session_state.signing_method = None
                                st.rerun()
            
            # Mostrar botón de descarga del ZIP si está disponible
            if "zip_file" in st.session_state and st.session_state.zip_file:
                try:
                    st.download_button(
                        label=t("download_zip"),
                        data=st.session_state.zip_file,
                        file_name=f"{st.session_state.username}_signed_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                        mime="application/zip",
                        key="download_zip"
                    )
                except Exception as e:
                    st.error(f"Error providing ZIP download: {e}")
            else:
                if uploaded_file and not st.session_state.signing_method:
                    st.warning("Por favor, selecciona un método de firma (RSA o ECDSA) antes de continuar.")
                elif not getattr(st.session_state, "zip_file", None):
                    st.info("Firma el documento para descargar el archivo ZIP con la firma y las claves.")
        
        with tabs[1]:  # Pestaña QR
            st.header(t("qr_tab"))
            qr_pdf_file = st.file_uploader(t("upload_pdf_for_qr"), type=["pdf"], key="qr_pdf_uploader")
            
            if qr_pdf_file:
                st.write(t("document_uploaded", filename=qr_pdf_file.name))
                
                if st.button(t("generate_qr_button")):
                    # Guardar el PDF subido temporalmente en S3
                    user_prefix = f"{S3_KEY_PREFIX}{st.session_state.username}/documents/"
                    pdf_key = f"{user_prefix}{qr_pdf_file.name}"
                    try:
                        s3_client.upload_fileobj(qr_pdf_file, S3_BUCKET_NAME, pdf_key)
                    except Exception as e:
                        st.error(f"Error uploading PDF to S3: {e}")
                        st.stop()
                    
                    # Generar nombre de salida para el PDF con QR
                    base, ext = os.path.splitext(qr_pdf_file.name)
                    output_pdf_key = f"{user_prefix}{base}_qr{ext}"
                    
                    # Descargar el PDF temporalmente para procesarlo
                    temp_pdf_path = f"temp_{qr_pdf_file.name}"
                    s3_client.download_file(S3_BUCKET_NAME, pdf_key, temp_pdf_path)
                    
                    # Llamar a la función de qr.py para insertar el QR
                    temp_output_path = f"temp_{base}_qr{ext}"
                    try:
                        insertar_qr_en_pdf(temp_pdf_path, temp_output_path)
                        st.success(t("qr_generation_success"))
                        # Subir el PDF con QR a S3
                        s3_client.upload_file(temp_output_path, S3_BUCKET_NAME, output_pdf_key)
                        # Leer el PDF generado para descarga
                        with open(temp_output_path, "rb") as f:
                            st.session_state.qr_pdf_content = f.read()
                        st.session_state.qr_pdf_filename = f"{base}_qr{ext}"
                    except Exception as e:
                        st.error(f"Error generating PDF with QR: {e}")
                        st.session_state.qr_pdf_content = None
                        st.session_state.qr_pdf_filename = None
                    
                    # Limpiar archivos temporales
                    if os.path.exists(temp_pdf_path):
                        os.remove(temp_pdf_path)
                    if os.path.exists(temp_output_path):
                        os.remove(temp_output_path)
                
                # Botón para descargar el PDF con QR
                if "qr_pdf_content" in st.session_state and st.session_state.qr_pdf_content:
                    st.download_button(
                        label=t("download_pdf_with_qr"),
                        data=st.session_state.qr_pdf_content,
                        file_name=st.session_state.qr_pdf_filename,
                        mime="application/pdf",
                        key="download_qr_pdf"
                    )

        with tabs[2]:  # Pestaña Verificar Documento
            st.header(t("verify_header"))
            verify_file = st.file_uploader(t("upload_verify"), type=["pdf"], key="verify_doc")
            signature_file = st.file_uploader(t("upload_signature"), type=["sig"], key="verify_sig")
            public_key_file = st.file_uploader(t("upload_public_key"), type=["pem"], key="verify_pub")
            
            if verify_file and signature_file and public_key_file:
                st.write(t("document_uploaded", filename=verify_file.name))
                with st.form("verify_form"):
                    verify_button = st.form_submit_button(t("verify_button"))
                    if verify_button:
                        # Guardar archivos subidos en S3
                        user_prefix = f"{S3_KEY_PREFIX}{st.session_state.username}/documents/"
                        doc_key = f"{user_prefix}{verify_file.name}"
                        sig_key = f"{user_prefix}{signature_file.name}"
                        pub_key = f"{user_prefix}{public_key_file.name}"
                        
                        try:
                            s3_client.upload_fileobj(verify_file, S3_BUCKET_NAME, doc_key)
                            s3_client.upload_fileobj(signature_file, S3_BUCKET_NAME, sig_key)
                            s3_client.upload_fileobj(public_key_file, S3_BUCKET_NAME, pub_key)
                        except Exception as e:
                            st.error(f"Error uploading files to S3: {e}")
                            st.stop()
                        
                        # Verificar documento
                        is_valid, message = verify_document(doc_key, sig_key, pub_key)
                        
                        if is_valid:
                            st.success(t("verify_success"))
                            st.write(t("verify_details"))
                            st.write(t("verified_on", timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                            st.write(t("verify_caption"))
                        else:
                            st.error(t("verify_error", error=message))

        with tabs[3]:  # Pestaña Descargar Archivos de Alumnos
            st.header(t("download_files_tab"))
            # Listar todos los usuarios con rol "student"
            df = pd.read_csv(USER_FILE)
            students = df[df["role"] == "student"]["username"].tolist()
            
            if students:
                selected_student = st.selectbox(t("select_user"), students)
                if st.button(t("download_user_files")):
                    # Listar archivos del usuario seleccionado en S3
                    user_prefix = f"{S3_KEY_PREFIX}{selected_student}/documents/"
                    try:
                        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=user_prefix)
                        files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'] != user_prefix]
                        if files:
                            zip_content = create_zip_file_from_s3(files)
                            st.download_button(
                                label=t("download_zip"),
                                data=zip_content,
                                file_name=f"{selected_student}_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                                mime="application/zip",
                                key=f"download_zip_{selected_student}"
                            )
                        else:
                            st.warning(t("no_files"))
                    except Exception as e:
                        st.error(f"Error listing files for {selected_student}: {e}")
            else:
                st.warning("No hay usuarios con rol 'student' registrados.")

    elif st.session_state.role == "student":
        tabs = st.tabs([t("files_tab")])
        
        
        with tabs[0]:  # Pestaña Mis Archivos
            st.header(t("files_tab"))
            # Listar archivos del usuario "student" en S3
            user_prefix = f"{S3_KEY_PREFIX}{st.session_state.username}/documents/"
            try:
                response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=user_prefix)
                files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'] != user_prefix]
                if files:
                    st.write("Archivos disponibles:")
                    for file_key in files:
                        file_name = file_key.split('/')[-1]
                        st.write(file_name)
                        # Generar un enlace de descarga para cada archivo
                        try:
                            # Generar un URL presignado para descarga segura
                            download_url = s3_client.generate_presigned_url(
                                'get_object',
                                Params={'Bucket': S3_BUCKET_NAME, 'Key': file_key},
                                ExpiresIn=3600  # URL válida por 1 hora
                            )
                            st.markdown(f"[Descargar {file_name}]({download_url})")
                        except Exception as e:
                            st.error(f"Error generating download link for {file_name}: {e}")
                else:
                    st.warning(t("no_files"))
            except Exception as e:
                st.error(f"Error listing your files: {e}")

# Agregar texto al final de la página
st.markdown(
    '<div class="footer-text">© 2025 App de Firma Digital</div>'
    '</br>'
    'Nathan Isaac García Larios A01749595@tec.mx </br>'
    'Tamara Alejandra Ortiz Villareal A01750582@tec.mx</br>'
    'Ximena Serna Mendoza A01749870@tec.mx</br>'
    'Profesor: Eliseo Sarmiento Rosales ',
    unsafe_allow_html=True
)
