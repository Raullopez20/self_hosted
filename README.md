# Password Manager - Gestor de Contraseñas Seguro

Este proyecto es un gestor de contraseñas web seguro, desarrollado en Python con Flask, y diseñado para ser desplegado en un entorno Windows Server con IIS. Está orientado a empresas que necesitan una solución robusta para la gestión de contraseñas, con múltiples niveles de acceso y seguridad avanzada.

## 🚀 Instalación y Configuración

### 1. Preparar el Entorno

```bash
# Activar el entorno virtual
.venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Configurar Base de Datos MySQL

Crear una base de datos MySQL llamada `password_manager`:

```sql
CREATE DATABASE password_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pm_user'@'localhost' IDENTIFIED BY 'contraseña_segura';
GRANT ALL PRIVILEGES ON password_manager.* TO 'pm_user'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Configurar Variables de Entorno

Edita el archivo `.env` con tus datos:

```env
# Base de datos
DB_HOST=localhost
DB_PORT=3306
DB_NAME=password_manager
DB_USER=pm_user
DB_PASSWORD=contraseña_segura

# Seguridad (CAMBIAR EN PRODUCCIÓN)
SECRET_KEY=tu_clave_secreta_muy_larga_y_aleatoria_de_al_menos_50_caracteres
ENCRYPTION_KEY=clave_maestra_para_cifrar_contraseñas_32_caracteres

# Correo para 2FA (opcional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=tu_email@gmail.com
MAIL_PASSWORD=tu_password_app_gmail
```

### 4. Inicializar la Base de Datos

```bash
python main.py
```

Esto creará las tablas automáticamente y un usuario administrador por defecto:
- **Usuario:** admin
- **Contraseña:** admin123 (cambiar inmediatamente)

### 5. Configurar IIS (Producción)

El archivo `web.config` ya está configurado. Solo actualiza las rutas de Python si es necesario.

### 6. Acceder a la Aplicación

- **Desarrollo:** http://localhost:5000
- **Producción:** Tu dominio configurado en IIS

## 🔐 Funcionalidades Implementadas

### ✅ Seguridad
- [x] Cifrado AES-256 para contraseñas almacenadas
- [x] Contraseñas de usuario hasheadas con bcrypt
- [x] Autenticación de dos factores (2FA) con TOTP
- [x] Protección CSRF en todos los formularios
- [x] Sanitización XSS automática
- [x] Headers de seguridad configurados
- [x] Logout automático por inactividad
- [x] Logs de acceso completos

### ✅ Gestión de Usuarios
- [x] Roles: Administrador, Editor, Solo Lectura
- [x] Departamentos con acceso segregado
- [x] Gestión completa de usuarios (admin)
- [x] Perfil de usuario con cambio de contraseña

### ✅ Gestión de Contraseñas
- [x] CRUD completo de contraseñas
- [x] Búsqueda avanzada con filtros
- [x] Sistema de etiquetas
- [x] Fechas de caducidad y alertas
- [x] Historial de cambios
- [x] Generador de contraseñas seguras
- [x] Evaluación de fortaleza de contraseñas

### ✅ Importación/Exportación
- [x] Exportación a CSV cifrado
- [x] Importación desde CSV cifrado
- [x] Compatible con otros gestores (KeePass, Bitwarden)

### ✅ Interfaz
- [x] Diseño responsivo (móvil/escritorio)
- [x] Modo oscuro/claro
- [x] Interfaz moderna con TailwindCSS
- [x] Notificaciones y mensajes flash
- [x] Modales para visualización segura

### ✅ Administración
- [x] Panel de administración completo
- [x] Gestión de departamentos
- [x] Logs de acceso y auditoría
- [x] Estadísticas en tiempo real

### ✅ Tecnologías Usadas
- Python 3.10+
- Flask
- MySQL
- SQLAlchemy
- Flask-WTF
- Flask-Login
- Flask-Mail
- cryptography
- bcrypt
- pyotp
- TailwindCSS
- IIS con wfastcgi

## 🛡️ Seguridad en Producción

### Cambios Obligatorios Antes de Usar:

1. **Cambiar credenciales por defecto:**
   ```
   Usuario: admin
   Contraseña: admin123
   ```

2. **Generar claves seguras:**
   ```bash
   # Generar SECRET_KEY
   python -c "import secrets; print(secrets.token_urlsafe(50))"
   
   # Generar ENCRYPTION_KEY
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. **Configurar HTTPS en IIS**

4. **Configurar backup automático de la base de datos**

5. **Habilitar 2FA para todos los administradores**


## 📱 Uso de la Aplicación

### Primer Acceso
1. Accede con admin/admin123
2. Cambia la contraseña inmediatamente
3. Configura 2FA en tu perfil
4. Crea departamentos necesarios
5. Crea usuarios para cada departamento

### Gestión Diaria
- **Editores:** pueden crear/editar contraseñas de su departamento
- **Solo Lectura:** pueden ver contraseñas de su departamento
- **Administradores:** acceso completo al sistema

### Funcionalidades Destacadas
- **Visualización segura:** Las contraseñas se muestran en modales seguros
- **Copiar al portapapeles:** Un clic para copiar contraseñas
- **Generador integrado:** Crea contraseñas seguras personalizables
- **Búsqueda avanzada:** Encuentra contraseñas por nombre, usuario, etiquetas
- **Alertas de caducidad:** Notificaciones de contraseñas que expiran

## 🔧 Mantenimiento

### Backup Regular
```bash
# Backup de base de datos
mysqldump -u pm_user -p password_manager > backup_$(date +%Y%m%d).sql

# Backup de archivos de aplicación
tar -czf app_backup_$(date +%Y%m%d).tar.gz /ruta/a/aplicacion
```

### Logs de Sistema
Los logs se almacenan en la tabla `access_logs` y incluyen:
- Inicios de sesión
- Visualización de contraseñas
- Creación/edición/eliminación
- Exportaciones/importaciones

### Actualización de Dependencias
```bash
pip list --outdated
pip install --upgrade package_name
```

## 🆘 Solución de Problemas

### Error de Conexión a Base de Datos
- Verificar credenciales en `.env`
- Confirmar que MySQL está ejecutándose
- Verificar permisos del usuario de BD

### Error 500 en IIS
- Revisar logs de IIS
- Verificar rutas de Python en web.config
- Confirmar que wfastcgi está instalado

### Problemas de 2FA
- Verificar sincronización de hora del servidor
- Regenerar secreto 2FA si es necesario

## 📞 Soporte

Para soporte técnico o reportar bugs, revisa los logs de la aplicación y contacta al administrador del sistema.

---

**¡Tu gestor de contraseñas seguro está listo para usar!** 🔐
