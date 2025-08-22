from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import bcrypt
import secrets
import pyotp
from cryptography.fernet import Fernet
import base64
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'editor', 'readonly'), default='readonly')
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relaciones
    department = db.relationship('Department', backref='users')
    access_logs = db.relationship('AccessLog', backref='user', lazy='dynamic')

    def set_password(self, password):
        """Hashea y guarda la contraseña del usuario"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Verifica la contraseña del usuario"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def generate_2fa_secret(self):
        """Genera un secreto para 2FA"""
        self.two_factor_secret = pyotp.random_base32()
        return self.two_factor_secret

    def get_2fa_uri(self, app_name):
        """Obtiene la URI para configurar 2FA"""
        if self.two_factor_secret:
            return pyotp.totp.TOTP(self.two_factor_secret).provisioning_uri(
                name=self.username,
                issuer_name=app_name
            )
        return None

    def verify_2fa_token(self, token):
        """Verifica el token de 2FA"""
        if self.two_factor_secret:
            totp = pyotp.TOTP(self.two_factor_secret)
            return totp.verify(token, valid_window=1)
        return False

    def can_access_department(self, department_id):
        """Verifica si el usuario puede acceder a un departamento"""
        if self.role == 'admin':
            return True
        return self.department_id == department_id

    def can_edit(self):
        """Verifica si el usuario puede editar"""
        return self.role in ['admin', 'editor']

    def can_admin(self):
        """Verifica si el usuario es administrador"""
        return self.role == 'admin'

class Department(db.Model):
    __tablename__ = 'departments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones - Cambiar lazy='dynamic' por lazy='select' para evitar el error de eager loading
    passwords = db.relationship('Password', backref='department', lazy='select')

class Password(db.Model):
    __tablename__ = 'passwords'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Nombre del recurso
    username = db.Column(db.String(100), nullable=True)  # Usuario para el recurso
    encrypted_password = db.Column(db.Text, nullable=False)  # Contraseña cifrada
    url = db.Column(db.String(500), nullable=True)  # URL opcional
    notes = db.Column(db.Text, nullable=True)  # Observaciones
    tags = db.Column(db.String(500), nullable=True)  # Etiquetas separadas por comas
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # Fecha de caducidad
    is_expired = db.Column(db.Boolean, default=False)

    # Relaciones
    creator = db.relationship('User', backref='created_passwords')
    access_logs = db.relationship('AccessLog', backref='password', lazy='dynamic')
    history = db.relationship('PasswordHistory', backref='password', lazy='dynamic')

    def set_password(self, plain_password, encryption_key):
        """Cifra y guarda la contraseña"""
        fernet = Fernet(self._get_key(encryption_key))
        self.encrypted_password = fernet.encrypt(plain_password.encode()).decode()

    def get_password(self, encryption_key):
        """Descifra y devuelve la contraseña"""
        fernet = Fernet(self._get_key(encryption_key))
        return fernet.decrypt(self.encrypted_password.encode()).decode()

    def _get_key(self, encryption_key):
        """Genera una clave Fernet válida"""
        key_bytes = encryption_key.encode()
        # Asegurar que la clave tenga 32 bytes
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b'0')
        else:
            key_bytes = key_bytes[:32]
        return base64.urlsafe_b64encode(key_bytes)

    def check_expiry(self):
        """Verifica si la contraseña ha caducado"""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            self.is_expired = True
            db.session.commit()
        return self.is_expired

    def get_tags_list(self):
        """Devuelve las etiquetas como lista"""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',') if tag.strip()]
        return []

    def set_tags_list(self, tags_list):
        """Establece las etiquetas desde una lista"""
        self.tags = ', '.join(tags_list) if tags_list else None

class PasswordHistory(db.Model):
    __tablename__ = 'password_history'

    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.Integer, db.ForeignKey('passwords.id'), nullable=False)
    encrypted_old_password = db.Column(db.Text, nullable=False)
    changed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    change_reason = db.Column(db.String(200), nullable=True)

    # Relaciones
    changer = db.relationship('User', backref='password_changes')

class AccessLog(db.Model):
    __tablename__ = 'access_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_id = db.Column(db.Integer, db.ForeignKey('passwords.id'), nullable=True)
    action = db.Column(db.Enum('login', 'logout', 'view', 'create', 'update', 'delete', 'export', 'import', 'disable_2fa'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.String(500), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    __tablename__ = 'settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(200), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
