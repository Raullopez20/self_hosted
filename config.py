import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'clave-super-secreta-cambiar-en-produccion'

    # Configuración de base de datos MySQL
    DB_HOST = os.environ.get('DB_HOST') or 'localhost'
    DB_PORT = os.environ.get('DB_PORT') or '3306'
    DB_NAME = os.environ.get('DB_NAME') or 'password_manager'
    DB_USER = os.environ.get('DB_USER') or 'root'
    DB_PASSWORD = os.environ.get('DB_PASSWORD') or ''

    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configuración de correo para 2FA
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    # Configuración de encriptación
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or 'clave-maestra-default-cambiar'

    # Configuración de la aplicación
    APP_NAME = os.environ.get('APP_NAME') or 'Password Manager'
    
    # Configuración CSRF mejorada para acceso remoto
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 7200  # 2 horas en lugar de 1
    WTF_CSRF_SSL_STRICT = False  # Permitir CSRF sin SSL
    WTF_CSRF_CHECK_DEFAULT = False  # No verificar CSRF por defecto
    WTF_CSRF_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']  # Solo para estos métodos

    # Configuración de sesiones - Mejorada para acceso remoto
    PERMANENT_SESSION_LIFETIME = 7200  # 2 horas
    SESSION_COOKIE_SECURE = False  # False para permitir HTTP
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = None  # Cambiar a None para permitir cross-site
    SESSION_COOKIE_DOMAIN = None  # Permitir cualquier dominio
