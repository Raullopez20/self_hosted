import secrets
import string
import hashlib
import hmac
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import csv
import io
from datetime import datetime
import os
import re
from urllib.parse import urlparse

class PasswordGenerator:
    """Generador de contraseñas seguras"""

    @staticmethod
    def generate(length=16, include_uppercase=True, include_lowercase=True,
                include_numbers=True, include_symbols=True, exclude_ambiguous=True):
        """Genera una contraseña aleatoria segura"""

        characters = ""

        if include_lowercase:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = chars.replace('l', '').replace('o', '')
            characters += chars

        if include_uppercase:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = chars.replace('I', '').replace('O', '')
            characters += chars

        if include_numbers:
            chars = string.digits
            if exclude_ambiguous:
                chars = chars.replace('0', '').replace('1', '')
            characters += chars

        if include_symbols:
            chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            characters += chars

        if not characters:
            raise ValueError("Debe incluir al menos un tipo de carácter")

        # Generar contraseña asegurando que tenga al menos un carácter de cada tipo seleccionado
        password = []

        # Agregar al menos un carácter de cada tipo seleccionado
        if include_lowercase:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = chars.replace('l', '').replace('o', '')
            password.append(secrets.choice(chars))

        if include_uppercase:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = chars.replace('I', '').replace('O', '')
            password.append(secrets.choice(chars))

        if include_numbers:
            chars = string.digits
            if exclude_ambiguous:
                chars = chars.replace('0', '').replace('1', '')
            password.append(secrets.choice(chars))

        if include_symbols:
            chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            password.append(secrets.choice(chars))

        # Completar el resto de la longitud
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))

        # Mezclar la contraseña
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    @staticmethod
    def check_strength(password):
        """Evalúa la fortaleza de una contraseña"""

        if not password:
            return {
                'score': 0,
                'strength': 'Muy Débil',
                'suggestions': ['La contraseña no puede estar vacía']
            }

        score = 0
        suggestions = []

        # Longitud
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            suggestions.append('Usa al menos 8 caracteres')

        # Variedad de caracteres
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_numbers = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))

        if has_lowercase:
            score += 1
        else:
            suggestions.append('Incluye letras minúsculas')

        if has_uppercase:
            score += 1
        else:
            suggestions.append('Incluye letras mayúsculas')

        if has_numbers:
            score += 1
        else:
            suggestions.append('Incluye números')

        if has_symbols:
            score += 2
        else:
            suggestions.append('Incluye símbolos (!@#$%^&*)')

        # Patrones comunes
        common_patterns = [
            r'123',
            r'abc',
            r'password',
            r'admin',
            r'qwerty',
            r'(\w)\1{2,}',  # Caracteres repetidos
        ]

        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                score -= 1
                suggestions.append('Evita patrones comunes o secuencias')
                break

        # Determinar nivel de fortaleza
        if score <= 2:
            strength = 'Muy Débil'
        elif score <= 4:
            strength = 'Débil'
        elif score <= 6:
            strength = 'Moderada'
        elif score <= 8:
            strength = 'Fuerte'
        else:
            strength = 'Muy Fuerte'

        return {
            'score': max(0, score),
            'strength': strength,
            'suggestions': suggestions[:3]  # Máximo 3 sugerencias
        }

class EncryptionHelper:
    """Helper para operaciones de cifrado"""

    @staticmethod
    def generate_key():
        """Genera una clave de cifrado"""
        return Fernet.generate_key()

    @staticmethod
    def derive_key(password, salt=None):
        """Deriva una clave desde una contraseña"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def encrypt_data(data, key):
        """Cifra datos con una clave"""
        f = Fernet(key)
        return f.encrypt(data.encode())

    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Descifra datos con una clave"""
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()

class CSVHelper:
    """Helper para operaciones con CSV"""

    @staticmethod
    def export_passwords(passwords, encryption_password, system_key):
        """Exporta contraseñas a CSV cifrado"""

        # Crear contenido CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Encabezados
        writer.writerow([
            'name',
            'username',
            'password',
            'url',
            'notes',
            'tags',
            'department'
        ])

        # Datos
        for password in passwords:
            # Descifrar la contraseña usando la clave del sistema
            decrypted_password = password.get_password(system_key)

            writer.writerow([
                password.name,
                password.username or '',
                decrypted_password,
                password.url or '',
                password.notes or '',
                password.tags or '',
                password.department.name if password.department else ''
            ])

        csv_content = output.getvalue()
        output.close()

        # Cifrar el CSV con la contraseña del usuario
        key, salt = EncryptionHelper.derive_key(encryption_password)
        encrypted_content = EncryptionHelper.encrypt_data(csv_content, key)

        # Combinar salt + datos cifrados en formato base64
        final_content = base64.b64encode(salt + encrypted_content).decode()

        return final_content

    @staticmethod
    def import_passwords(encrypted_csv_content, encryption_password):
        """Importa contraseñas desde CSV cifrado"""

        try:
            # Decodificar el contenido base64
            encrypted_data = base64.b64decode(encrypted_csv_content.encode())

            # Extraer salt (primeros 16 bytes) y datos cifrados
            salt = encrypted_data[:16]
            encrypted_content = encrypted_data[16:]

            # Derivar clave usando la contraseña y el salt
            key, _ = EncryptionHelper.derive_key(encryption_password, salt)

            # Descifrar el contenido
            csv_content = EncryptionHelper.decrypt_data(encrypted_content, key)

            # Procesar el CSV
            reader = csv.DictReader(io.StringIO(csv_content))
            passwords = []

            for row in reader:
                # Validar que las columnas requeridas existan
                if 'name' not in row or 'password' not in row:
                    continue

                passwords.append({
                    'name': row.get('name', '').strip(),
                    'username': row.get('username', '').strip(),
                    'password': row.get('password', '').strip(),
                    'url': row.get('url', '').strip(),
                    'notes': row.get('notes', '').strip(),
                    'tags': row.get('tags', '').strip(),
                    'department': row.get('department', '').strip()
                })

            return passwords

        except Exception as e:
            raise ValueError(f"Error al procesar el archivo cifrado: {str(e)}")

class SecurityHelper:
    """Helper para operaciones de seguridad"""

    @staticmethod
    def is_safe_url(target):
        """Verifica si una URL es segura para redirección"""
        if not target:
            return False

        ref_url = urlparse(target)

        # Solo permitir URLs relativas o del mismo dominio
        return not ref_url.netloc or ref_url.netloc == urlparse(request.url).netloc

    @staticmethod
    def generate_csrf_token():
        """Genera un token CSRF"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def validate_password_complexity(password):
        """Valida que una contraseña cumpla con los requisitos mínimos"""

        if len(password) < 8:
            return False, "La contraseña debe tener al menos 8 caracteres"

        if not re.search(r'[a-z]', password):
            return False, "La contraseña debe incluir al menos una letra minúscula"

        if not re.search(r'[A-Z]', password):
            return False, "La contraseña debe incluir al menos una letra mayúscula"

        if not re.search(r'\d', password):
            return False, "La contraseña debe incluir al menos un número"

        return True, "Contraseña válida"

    @staticmethod
    def sanitize_filename(filename):
        """Sanitiza un nombre de archivo"""
        # Remover caracteres peligrosos
        filename = re.sub(r'[^\w\s.-]', '', filename)
        # Limitar longitud
        filename = filename[:100]
        # Evitar nombres reservados
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] + [f'LPT{i}' for i in range(1, 10)]
        if filename.upper() in reserved_names:
            filename = f"file_{filename}"

        return filename

class TwoFactorHelper:
    """Helper para autenticación de dos factores"""

    @staticmethod
    def generate_backup_codes():
        """Genera códigos de respaldo para 2FA"""
        codes = []
        for _ in range(10):
            code = '-'.join([
                ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
                for _ in range(2)
            ])
            codes.append(code)
        return codes

    @staticmethod
    def hash_backup_code(code):
        """Hashea un código de respaldo"""
        return hashlib.sha256(code.encode()).hexdigest()

    @staticmethod
    def verify_backup_code(code, hashed_code):
        """Verifica un código de respaldo"""
        return hashlib.sha256(code.encode()).hexdigest() == hashed_code

class AuditHelper:
    """Helper para auditoría y logs"""

    @staticmethod
    def format_user_agent(user_agent_string):
        """Formatea el user agent para mostrar información útil"""
        if not user_agent_string:
            return "Desconocido"

        # Simplificar el user agent para mostrar solo info relevante
        if "Chrome" in user_agent_string:
            return "Chrome"
        elif "Firefox" in user_agent_string:
            return "Firefox"
        elif "Safari" in user_agent_string:
            return "Safari"
        elif "Edge" in user_agent_string:
            return "Edge"
        else:
            return "Otro navegador"

    @staticmethod
    def get_client_ip(request):
        """Obtiene la IP real del cliente considerando proxies"""
        # Verificar headers de proxy
        forwarded_ips = request.headers.get('X-Forwarded-For')
        if forwarded_ips:
            return forwarded_ips.split(',')[0].strip()

        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip

        return request.remote_addr

class ValidationHelper:
    """Helper para validaciones"""

    @staticmethod
    def validate_email(email):
        """Valida formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_username(username):
        """Valida formato de username"""
        # Solo letras, números, guiones y guiones bajos
        pattern = r'^[a-zA-Z0-9._-]{3,30}$'
        return re.match(pattern, username) is not None

    @staticmethod
    def validate_url(url):
        """Valida formato de URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    @staticmethod
    def sanitize_input(input_string, max_length=None):
        """Sanitiza entrada de usuario"""
        if not input_string:
            return ""

        # Remover caracteres de control
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_string)

        # Limitar longitud si se especifica
        if max_length:
            sanitized = sanitized[:max_length]

        return sanitized.strip()
