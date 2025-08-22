from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import os
from datetime import datetime, timedelta
import io
import qrcode
import base64
from sqlalchemy.orm import joinedload

# Importar módulos locales
from config import Config
from models import db, User, Department, Password, PasswordHistory, AccessLog, Settings
from forms import *
from utils import PasswordGenerator, EncryptionHelper, CSVHelper, SecurityHelper

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Configurar proxy para IIS
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Inicializar extensiones
    db.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'  # Corregido: era 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
    login_manager.login_message_category = 'warning'

    mail = Mail(app)
    csrf = CSRFProtect(app)

    # Configuración específica para CSRF con acceso remoto
    @csrf.exempt
    def csrf_exempt_routes():
        # Lista de rutas que pueden estar exentas de CSRF si es necesario
        pass

    # Configurar headers personalizados para CSRF
    @app.before_request
    def before_request():
        # Permitir CSRF desde diferentes orígenes para acceso remoto
        if request.method == "POST":
            # Verificar si el token CSRF está presente en headers o formulario
            token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
            if not token and not request.path.startswith('/static/'):
                # Log para debugging
                app.logger.warning(f"CSRF token missing for {request.path} from {request.remote_addr}")

    # Configurar headers CORS para permitir acceso remoto
    @app.after_request
    def after_request(response):
        # Permitir cookies cross-origin para acceso remoto
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRFToken'

        # Configurar cookies para acceso remoto
        if 'Set-Cookie' in response.headers:
            # Permitir cookies sin secure flag para HTTP
            cookie_header = response.headers['Set-Cookie']
            if 'Secure;' in cookie_header:
                response.headers['Set-Cookie'] = cookie_header.replace('Secure;', '')

        return response

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Función para registrar logs de acceso
    def log_access(action, password_id=None, details=None):
        if current_user.is_authenticated:
            log = AccessLog(
                user_id=current_user.id,
                password_id=password_id,
                action=action,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                details=details
            )
            db.session.add(log)
            db.session.commit()

    # Rutas de autenticación
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()

            if user and user.check_password(form.password.data) and user.is_active:
                # Verificar 2FA si está habilitado
                if user.two_factor_enabled:
                    if not form.two_factor_token.data:
                        flash('Se requiere código de autenticación de dos factores.', 'warning')
                        return render_template('auth/login.html', form=form, require_2fa=True)

                    if not user.verify_2fa_token(form.two_factor_token.data):
                        flash('Código de autenticación inválido.', 'error')
                        return render_template('auth/login.html', form=form, require_2fa=True)

                login_user(user, remember=form.remember_me.data)
                user.last_login = datetime.utcnow()
                db.session.commit()

                log_access('login')
                flash(f'¡Bienvenido, {user.username}!', 'success')

                next_page = request.args.get('next')
                if not next_page or not SecurityHelper.is_safe_url(next_page):
                    next_page = url_for('dashboard')
                return redirect(next_page)
            else:
                flash('Usuario o contraseña incorrectos.', 'error')

        return render_template('auth/login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        log_access('logout')
        logout_user()
        flash('Has cerrado sesión correctamente.', 'info')
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    @login_required
    def register():
        if not current_user.can_admin():
            flash('No tienes permisos para registrar usuarios.', 'error')
            return redirect(url_for('dashboard'))

        form = RegisterForm()
        departments = Department.query.all()
        form.department_id.choices = [(0, 'Sin departamento')] + [(d.id, d.name) for d in departments]

        if form.validate_on_submit():
            # Verificar que el usuario no exista
            if User.query.filter_by(username=form.username.data).first():
                flash('El nombre de usuario ya existe.', 'error')
                return render_template('auth/register.html', form=form)

            if User.query.filter_by(email=form.email.data).first():
                flash('El email ya está registrado.', 'error')
                return render_template('auth/register.html', form=form)

            user = User(
                username=form.username.data,
                email=form.email.data,
                role=form.role.data,
                department_id=form.department_id.data if form.department_id.data != 0 else None
            )
            user.set_password(form.password.data)

            db.session.add(user)
            db.session.commit()

            flash(f'Usuario {user.username} creado exitosamente.', 'success')
            return redirect(url_for('admin_users'))

        return render_template('auth/register.html', form=form)

    # Ruta principal
    @app.route('/')
    @login_required
    def dashboard():
        # Estadísticas básicas
        total_passwords = Password.query.filter(
            Password.department_id == current_user.department_id if not current_user.can_admin() else True
        ).count()

        expired_passwords = Password.query.filter(
            Password.is_expired == True,
            Password.department_id == current_user.department_id if not current_user.can_admin() else True
        ).count()

        recent_passwords = Password.query.filter(
            Password.department_id == current_user.department_id if not current_user.can_admin() else True
        ).order_by(Password.created_at.desc()).limit(5).all()

        return render_template('dashboard.html',
                             total_passwords=total_passwords,
                             expired_passwords=expired_passwords,
                             recent_passwords=recent_passwords)

    # Rutas de contraseñas
    @app.route('/passwords')
    @login_required
    def list_passwords():
        form = SearchForm()
        departments = Department.query.all()
        form.department_id.choices = [('', 'Todos los departamentos')] + [(str(d.id), d.name) for d in departments]

        query = Password.query

        # Filtrar por departamento si no es admin
        if not current_user.can_admin():
            query = query.filter(Password.department_id == current_user.department_id)

        # Aplicar filtros de búsqueda
        if request.args.get('query'):
            search_term = f"%{request.args.get('query')}%"
            query = query.filter(
                db.or_(
                    Password.name.like(search_term),
                    Password.username.like(search_term),
                    Password.notes.like(search_term),
                    Password.tags.like(search_term)
                )
            )

        if request.args.get('department_id'):
            query = query.filter(Password.department_id == request.args.get('department_id'))

        if request.args.get('expired_only'):
            query = query.filter(Password.is_expired == True)

        passwords = query.order_by(Password.updated_at.desc()).all()

        # Verificar caducidad de contraseñas
        for password in passwords:
            password.check_expiry()

        return render_template('passwords/list.html', passwords=passwords, form=form)

    @app.route('/passwords/new', methods=['GET', 'POST'])
    @login_required
    def new_password():
        if not current_user.can_edit():
            flash('No tienes permisos para crear contraseñas.', 'error')
            return redirect(url_for('list_passwords'))

        form = PasswordEntryForm()
        departments = Department.query.all()

        if current_user.can_admin():
            form.department_id.choices = [(d.id, d.name) for d in departments]
        else:
            form.department_id.choices = [(current_user.department_id, current_user.department.name)]
            form.department_id.data = current_user.department_id

        if form.validate_on_submit():
            password_entry = Password(
                name=form.name.data,
                username=form.username.data,
                url=form.url.data,
                notes=form.notes.data,
                department_id=form.department_id.data,
                created_by=current_user.id,
                expires_at=form.expires_at.data
            )

            # Cifrar la contraseña
            password_entry.set_password(form.password.data, app.config['ENCRYPTION_KEY'])

            # Procesar etiquetas
            if form.tags.data:
                tags_list = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
                password_entry.set_tags_list(tags_list)

            db.session.add(password_entry)
            db.session.commit()

            log_access('create', password_entry.id, f'Creada entrada: {password_entry.name}')
            flash('Contraseña guardada exitosamente.', 'success')
            return redirect(url_for('list_passwords'))

        return render_template('passwords/form.html', form=form, title='Nueva Contraseña')

    @app.route('/passwords/<int:id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_password(id):
        password_entry = Password.query.get_or_404(id)

        # Verificar permisos
        if not current_user.can_edit() or (not current_user.can_admin() and password_entry.department_id != current_user.department_id):
            flash('No tienes permisos para editar esta contraseña.', 'error')
            return redirect(url_for('list_passwords'))

        form = PasswordEditForm()
        departments = Department.query.all()

        if current_user.can_admin():
            form.department_id.choices = [(d.id, d.name) for d in departments]
        else:
            form.department_id.choices = [(current_user.department_id, current_user.department.name)]

        if form.validate_on_submit():
            # Guardar historial si cambia la contraseña
            if form.password.data:
                history = PasswordHistory(
                    password_id=password_entry.id,
                    encrypted_old_password=password_entry.encrypted_password,
                    changed_by=current_user.id,
                    change_reason=form.change_reason.data
                )
                db.session.add(history)

                # Actualizar con nueva contraseña
                password_entry.set_password(form.password.data, app.config['ENCRYPTION_KEY'])

            # Actualizar otros campos
            password_entry.name = form.name.data
            password_entry.username = form.username.data
            password_entry.url = form.url.data
            password_entry.notes = form.notes.data
            password_entry.department_id = form.department_id.data
            password_entry.expires_at = form.expires_at.data
            password_entry.updated_at = datetime.utcnow()

            # Procesar etiquetas
            if form.tags.data:
                tags_list = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
                password_entry.set_tags_list(tags_list)
            else:
                password_entry.tags = None

            db.session.commit()

            log_access('update', password_entry.id, f'Actualizada entrada: {password_entry.name}')
            flash('Contraseña actualizada exitosamente.', 'success')
            return redirect(url_for('list_passwords'))

        # Prellenar formulario
        if request.method == 'GET':
            form.name.data = password_entry.name
            form.username.data = password_entry.username
            form.url.data = password_entry.url
            form.notes.data = password_entry.notes
            form.department_id.data = password_entry.department_id
            form.expires_at.data = password_entry.expires_at
            form.tags.data = password_entry.tags

        return render_template('passwords/form.html', form=form, title='Editar Contraseña', password=password_entry)

    @app.route('/passwords/<int:id>/view')
    @login_required
    def view_password(id):
        password_entry = Password.query.get_or_404(id)

        # Verificar permisos
        if not current_user.can_access_department(password_entry.department_id):
            flash('No tienes permisos para ver esta contraseña.', 'error')
            return redirect(url_for('list_passwords'))

        # Descifrar contraseña
        decrypted_password = password_entry.get_password(app.config['ENCRYPTION_KEY'])

        log_access('view', password_entry.id, f'Visualizada entrada: {password_entry.name}')

        return jsonify({
            'password': decrypted_password,
            'strength': PasswordGenerator.check_strength(decrypted_password)
        })

    @app.route('/passwords/<int:id>/delete', methods=['POST'])
    @login_required
    def delete_password(id):
        password_entry = Password.query.get_or_404(id)

        # Verificar permisos
        if not current_user.can_edit() or (not current_user.can_admin() and password_entry.department_id != current_user.department_id):
            flash('No tienes permisos para eliminar esta contraseña.', 'error')
            return redirect(url_for('list_passwords'))

        # Eliminar registros relacionados
        PasswordHistory.query.filter_by(password_id=id).delete()
        AccessLog.query.filter_by(password_id=id).delete()

        log_access('delete', password_entry.id, f'Eliminada entrada: {password_entry.name}')

        db.session.delete(password_entry)
        db.session.commit()

        flash('Contraseña eliminada exitosamente.', 'success')
        return redirect(url_for('list_passwords'))

    # Generador de contraseñas
    @app.route('/generate-password', methods=['POST'])
    @login_required
    def generate_password():
        form = PasswordGeneratorForm()
        if form.validate_on_submit():
            try:
                password = PasswordGenerator.generate(
                    length=form.length.data,
                    include_uppercase=form.include_uppercase.data,
                    include_lowercase=form.include_lowercase.data,
                    include_numbers=form.include_numbers.data,
                    include_symbols=form.include_symbols.data,
                    exclude_ambiguous=form.exclude_ambiguous.data
                )

                strength = PasswordGenerator.check_strength(password)

                return jsonify({
                    'password': password,
                    'strength': strength
                })
            except ValueError as e:
                return jsonify({'error': str(e)}), 400

        return jsonify({'error': 'Datos inválidos'}), 400

    # Rutas de 2FA
    @app.route('/setup-2fa', methods=['GET', 'POST'])
    @login_required
    def setup_2fa():
        if current_user.two_factor_enabled:
            flash('La autenticación de dos factores ya está habilitada.', 'info')
            return redirect(url_for('profile'))

        form = TwoFactorSetupForm()

        if request.method == 'GET':
            # Generar secreto para 2FA
            secret = current_user.generate_2fa_secret()
            db.session.commit()

            # Generar código QR
            qr_uri = current_user.get_2fa_uri(app.config['APP_NAME'])
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = io.BytesIO()
            img.save(img_buffer, 'PNG')
            img_buffer.seek(0)

            qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()

            return render_template('auth/setup_2fa.html', form=form,
                                 qr_code=qr_code_data, secret=secret)

        if form.validate_on_submit():
            if current_user.verify_2fa_token(form.token.data):
                current_user.two_factor_enabled = True
                db.session.commit()
                flash('Autenticación de dos factores habilitada exitosamente.', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Código de verificación inválido.', 'error')

        return render_template('auth/setup_2fa.html', form=form)

    @app.route('/disable-2fa', methods=['POST'])
    @login_required
    def disable_2fa():
        try:
            if current_user.two_factor_enabled:
                current_user.two_factor_enabled = False
                current_user.two_factor_secret = None
                db.session.commit()
                log_access('disable_2fa', details='2FA deshabilitado')
                flash('Autenticación de dos factores deshabilitada correctamente.', 'success')
            else:
                flash('2FA ya estaba deshabilitado.', 'info')
        except Exception as e:
            db.session.rollback()
            flash('Error al desactivar 2FA. Inténtalo de nuevo.', 'error')

        return redirect(url_for('profile'))

    # Rutas de perfil
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        form = ChangePasswordForm()

        if form.validate_on_submit():
            if current_user.check_password(form.current_password.data):
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Contraseña actualizada exitosamente.', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Contraseña actual incorrecta.', 'error')

        return render_template('auth/profile.html', form=form)

    # Rutas de administración
    @app.route('/admin/users')
    @login_required
    def admin_users():
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Construir la consulta base
        query = User.query

        # Aplicar filtros si existen
        search = request.args.get('search')
        if search:
            query = query.filter(
                db.or_(
                    User.username.like(f'%{search}%'),
                    User.email.like(f'%{search}%')
                )
            )

        role_filter = request.args.get('role')
        if role_filter:
            query = query.filter(User.role == role_filter)

        status_filter = request.args.get('status')
        if status_filter:
            is_active = status_filter == 'active'
            query = query.filter(User.is_active == is_active)

        # Ordenar y paginar
        users = query.order_by(User.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return render_template('admin/users.html', users=users)

    @app.route('/admin/users/<int:id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_user(id):
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        user = User.query.get_or_404(id)
        form = UserEditForm()

        departments = Department.query.all()
        form.department_id.choices = [(0, 'Sin departamento')] + [(d.id, d.name) for d in departments]

        if form.validate_on_submit():
            # Verificar que el username no esté en uso por otro usuario
            existing_user = User.query.filter(User.username == form.username.data, User.id != id).first()
            if existing_user:
                flash('El nombre de usuario ya está en uso.', 'error')
                return render_template('admin/edit_user.html', form=form, user=user)

            user.username = form.username.data
            user.email = form.email.data
            user.role = form.role.data
            user.department_id = form.department_id.data if form.department_id.data != 0 else None
            user.is_active = form.is_active.data

            # Manejar el cambio de contraseña si se proporcionó una nueva
            if form.password.data:
                user.set_password(form.password.data)
                log_access('update', password_id=None, details=f'Contraseña del usuario {user.username} cambiada por administrador')

            db.session.commit()
            flash('Usuario actualizado exitosamente.', 'success')

            # Log de la acción
            log_access('update', password_id=None, details=f'Usuario {user.username} editado')

            return redirect(url_for('admin_users'))

        # Prellenar formulario
        if request.method == 'GET':
            form.username.data = user.username
            form.email.data = user.email
            form.role.data = user.role
            form.department_id.data = user.department_id or 0
            form.is_active.data = user.is_active

        return render_template('admin/edit_user.html', form=form, user=user)

    @app.route('/admin/users/<int:id>/toggle-status', methods=['POST'])
    @login_required
    def admin_toggle_user_status(id):
        if not current_user.can_admin():
            return jsonify({'success': False, 'message': 'No tienes permisos para realizar esta acción'}), 403

        user = User.query.get_or_404(id)

        # No permitir desactivar al propio usuario admin
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'No puedes cambiar tu propio estado'}), 400

        # Cambiar el estado
        user.is_active = not user.is_active
        status_text = 'activado' if user.is_active else 'desactivado'

        db.session.commit()

        # Log de la acción
        log_access('update', password_id=None, details=f'Usuario {user.username} {status_text}')

        return jsonify({
            'success': True,
            'message': f'Usuario {status_text} exitosamente',
            'new_status': user.is_active
        })

    @app.route('/admin/users/<int:id>/delete', methods=['POST'])
    @login_required
    def admin_delete_user(id):
        if not current_user.can_admin():
            return jsonify({'success': False, 'message': 'No tienes permisos para realizar esta acción'}), 403

        user = User.query.get_or_404(id)

        # No permitir eliminar al propio usuario admin
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'No puedes eliminar tu propia cuenta'}), 400

        # Verificar si el usuario tiene contraseñas asociadas
        if user.created_passwords:
            return jsonify({
                'success': False,
                'message': 'No se puede eliminar el usuario porque tiene contraseñas asociadas'
            }), 400

        username = user.username

        # Eliminar logs asociados al usuario
        AccessLog.query.filter_by(user_id=id).delete()

        # Eliminar historial de contraseñas donde el usuario fue quien cambió
        PasswordHistory.query.filter_by(changed_by=id).delete()

        db.session.delete(user)
        db.session.commit()

        # Log de la acción
        log_access('delete', password_id=None, details=f'Usuario {username} eliminado')

        return jsonify({
            'success': True,
            'message': f'Usuario {username} eliminado exitosamente'
        })

    @app.route('/admin/departments')
    @login_required
    def admin_departments():
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        departments = Department.query.options(
            joinedload(Department.users),
            joinedload(Department.passwords)
        ).all()
        return render_template('admin/departments.html', departments=departments)

    @app.route('/admin/departments/new', methods=['GET', 'POST'])
    @login_required
    def admin_new_department():
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        form = DepartmentForm()

        if form.validate_on_submit():
            department = Department(
                name=form.name.data,
                description=form.description.data
            )
            db.session.add(department)
            db.session.commit()
            flash('Departamento creado exitosamente.', 'success')
            return redirect(url_for('admin_departments'))

        return render_template('admin/department_form.html', form=form, title='Nuevo Departamento')

    @app.route('/admin/departments/<int:id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_department(id):
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        department = Department.query.get_or_404(id)
        form = DepartmentForm()

        if form.validate_on_submit():
            # Verificar que el nombre no esté en uso por otro departamento
            existing_dept = Department.query.filter(Department.name == form.name.data, Department.id != id).first()
            if existing_dept:
                flash('El nombre del departamento ya está en uso.', 'error')
                return render_template('admin/department_form.html', form=form, title='Editar Departamento', department=department)

            department.name = form.name.data
            department.description = form.description.data
            db.session.commit()
            flash('Departamento actualizado exitosamente.', 'success')
            return redirect(url_for('admin_departments'))

        # Prellenar formulario
        if request.method == 'GET':
            form.name.data = department.name
            form.description.data = department.description

        return render_template('admin/department_form.html', form=form, title='Editar Departamento', department=department)

    @app.route('/admin/departments/<int:id>/delete', methods=['POST'])
    @login_required
    def admin_delete_department(id):
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        department = Department.query.get_or_404(id)

        # Verificar si tiene usuarios o contraseñas asociadas
        if department.users or department.passwords:
            flash('No se puede eliminar el departamento porque tiene usuarios o contraseñas asociadas.', 'error')
            return redirect(url_for('admin_departments'))

        db.session.delete(department)
        db.session.commit()
        flash('Departamento eliminado exitosamente.', 'success')
        return redirect(url_for('admin_departments'))

    @app.route('/admin/logs')
    @login_required
    def admin_logs():
        if not current_user.can_admin():
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Construir la consulta base
        query = AccessLog.query

        # Aplicar filtros
        action_filter = request.args.get('action')
        if action_filter:
            query = query.filter(AccessLog.action == action_filter)

        username_filter = request.args.get('username')
        if username_filter:
            query = query.join(User).filter(User.username.like(f'%{username_filter}%'))

        date_from = request.args.get('date_from')
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(AccessLog.timestamp >= from_date)
            except ValueError:
                pass

        date_to = request.args.get('date_to')
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d')
                # Agregar 1 día para incluir todo el día seleccionado
                to_date = to_date.replace(hour=23, minute=59, second=59)
                query = query.filter(AccessLog.timestamp <= to_date)
            except ValueError:
                pass

        # Ordenar y paginar
        logs = query.order_by(AccessLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return render_template('admin/logs.html', logs=logs)

    # Rutas de importación/exportación
    @app.route('/export', methods=['GET', 'POST'])
    @login_required
    def export_passwords():
        form = ExportForm()

        if current_user.can_admin():
            departments = Department.query.all()
            form.department_id.choices = [('', 'Todos los departamentos')] + [(str(d.id), d.name) for d in departments]
        else:
            # Si no es admin, solo puede exportar de su departamento
            if current_user.department:
                form.department_id.choices = [(str(current_user.department_id), current_user.department.name)]
                form.department_id.data = str(current_user.department_id)
            else:
                flash('No tienes un departamento asignado.', 'error')
                return redirect(url_for('dashboard'))

        if form.validate_on_submit():
            try:
                query = Password.query

                # Filtrar por departamento si no es admin
                if not current_user.can_admin():
                    query = query.filter(Password.department_id == current_user.department_id)
                elif form.department_id.data:
                    query = query.filter(Password.department_id == int(form.department_id.data))

                passwords = query.all()

                if not passwords:
                    flash('No hay contraseñas para exportar con los filtros seleccionados.', 'warning')
                    return render_template('tools/export.html', form=form)

                # Exportar usando la clave del sistema
                encrypted_csv = CSVHelper.export_passwords(
                    passwords,
                    form.encryption_password.data,
                    app.config['ENCRYPTION_KEY']
                )

                # Crear archivo en memoria
                output = io.BytesIO()
                output.write(encrypted_csv.encode())
                output.seek(0)

                log_access('export', details=f'Exportadas {len(passwords)} contraseñas')
                flash(f'Se exportaron {len(passwords)} contraseñas exitosamente.', 'success')

                return send_file(
                    output,
                    as_attachment=True,
                    download_name=f'passwords_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.enc',
                    mimetype='application/octet-stream'
                )

            except Exception as e:
                flash(f'Error al exportar: {str(e)}', 'error')
                app.logger.error(f'Error en exportación: {str(e)}')

        return render_template('tools/export.html', form=form)

    @app.route('/import', methods=['GET', 'POST'])
    @login_required
    def import_passwords():
        if not current_user.can_edit():
            flash('No tienes permisos para importar contraseñas.', 'error')
            return redirect(url_for('dashboard'))

        form = ImportForm()

        if current_user.can_admin():
            departments = Department.query.all()
            form.department_id.choices = [(d.id, d.name) for d in departments]
        else:
            # Si no es admin, solo puede importar a su departamento
            if current_user.department:
                form.department_id.choices = [(current_user.department_id, current_user.department.name)]
                form.department_id.data = current_user.department_id
            else:
                flash('No tienes un departamento asignado.', 'error')
                return redirect(url_for('dashboard'))

        if form.validate_on_submit():
            try:
                # Verificar que el departamento de destino existe
                target_department = Department.query.get(form.department_id.data)
                if not target_department:
                    flash('El departamento seleccionado no existe.', 'error')
                    return render_template('tools/import.html', form=form)

                # Obtener el contenido CSV (desde archivo o textarea)
                csv_content = None

                if form.csv_file_upload.data:
                    # Método de carga de archivo
                    uploaded_file = form.csv_file_upload.data
                    try:
                        csv_content = uploaded_file.read().decode('utf-8')
                    except UnicodeDecodeError:
                        flash('Error al leer el archivo. Asegúrate de que sea un archivo de texto válido.', 'error')
                        return render_template('tools/import.html', form=form)
                elif form.csv_file.data:
                    # Método de copiar/pegar
                    csv_content = form.csv_file.data
                else:
                    flash('Debes proporcionar un archivo o pegar el contenido del CSV.', 'error')
                    return render_template('tools/import.html', form=form)

                # Importar contraseñas usando el contenido obtenido
                passwords_data = CSVHelper.import_passwords(
                    csv_content,
                    form.encryption_password.data
                )

                if not passwords_data:
                    flash('No se encontraron contraseñas válidas en el archivo.', 'warning')
                    return render_template('tools/import.html', form=form)

                imported_count = 0
                skipped_count = 0

                for password_data in passwords_data:
                    # Verificar si ya existe una contraseña con el mismo nombre en el departamento
                    existing = Password.query.filter_by(
                        name=password_data['name'],
                        department_id=form.department_id.data
                    ).first()

                    if existing:
                        skipped_count += 1
                        continue

                    # Crear nueva entrada de contraseña
                    password_entry = Password(
                        name=password_data['name'],
                        username=password_data['username'],
                        url=password_data['url'],
                        notes=password_data['notes'],
                        department_id=form.department_id.data,
                        created_by=current_user.id
                    )

                    # Cifrar y establecer la contraseña
                    password_entry.set_password(password_data['password'], app.config['ENCRYPTION_KEY'])

                    # Procesar etiquetas si existen
                    if password_data['tags']:
                        tags_list = [tag.strip() for tag in password_data['tags'].split(',') if tag.strip()]
                        if tags_list:
                            password_entry.set_tags_list(tags_list)

                    db.session.add(password_entry)
                    imported_count += 1

                db.session.commit()

                # Crear mensaje de resultado
                message_parts = []
                if imported_count > 0:
                    message_parts.append(f'Se importaron {imported_count} contraseñas')
                if skipped_count > 0:
                    message_parts.append(f'se omitieron {skipped_count} duplicadas')

                message = ' y '.join(message_parts) + '.'

                log_access('import', details=f'Importadas {imported_count} contraseñas, omitidas {skipped_count}')
                flash(message, 'success')
                return redirect(url_for('list_passwords'))

            except ValueError as e:
                # Error de descifrado o formato
                flash(f'Error en el archivo: {str(e)}', 'error')
            except Exception as e:
                # Error general
                flash(f'Error al importar: {str(e)}', 'error')
                app.logger.error(f'Error en importación: {str(e)}')
                db.session.rollback()

        return render_template('tools/import.html', form=form)

    # Manejadores de errores
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    # Ruta para cambiar tema
    @app.route('/toggle-theme', methods=['POST'])
    @login_required
    def toggle_theme():
        try:
            # Obtener el tema actual de la sesión o establecer por defecto
            current_theme = session.get('theme', 'light')

            # Cambiar al tema opuesto
            new_theme = 'dark' if current_theme == 'light' else 'light'

            # Guardar en la sesión
            session['theme'] = new_theme
            session.permanent = True  # Hacer que la sesión sea permanente

            return jsonify({
                'success': True,
                'theme': new_theme,
                'message': f'Tema cambiado a {new_theme}'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # Context processor para hacer el tema disponible en todas las plantillas
    @app.context_processor
    def inject_theme():
        try:
            # Verificar si hay una sesión activa y es seguro acceder a ella
            if not hasattr(request, 'endpoint') or request.endpoint in ['static']:
                return {'current_theme': 'light'}

            # Detectar tema automáticamente si no está configurado
            if 'theme' not in session:
                # Detectar preferencia del navegador de forma segura
                user_agent = request.headers.get('User-Agent', '').lower()

                # Lógica simple de detección - solo detectar, no forzar
                if 'dark' in user_agent:
                    default_theme = 'dark'
                else:
                    default_theme = 'light'

                # Solo establecer en la sesión si no estamos en el proceso de logout
                if request.endpoint != 'logout':
                    try:
                        session['theme'] = default_theme
                    except:
                        # Si no se puede escribir en la sesión, usar el tema por defecto
                        return {'current_theme': default_theme}

                return {'current_theme': default_theme}

            return {'current_theme': session.get('theme', 'light')}

        except Exception as e:
            # En caso de cualquier error, devolver tema claro por defecto
            return {'current_theme': 'light'}

    return app

# Crear la aplicación
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        try:
            # Crear todas las tablas
            db.create_all()
            print("✓ Tablas de base de datos creadas exitosamente")

            # Crear usuario admin por defecto si no existe
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email="",
                    role='admin'
                )
                admin.set_password('admin123')  # Cambiar en producción
                db.session.add(admin)

                # Crear departamentos por defecto solo si no existen
                departments_to_create = [
                    ('IT', 'Departamento de Tecnología'),
                    ('Administración', 'Departamento Administrativo'),
                    ('Recursos Humanos', 'Departamento de RRHH'),
                    ('Finanzas', 'Departamento Financiero')
                ]

                for dept_name, dept_desc in departments_to_create:
                    existing_dept = Department.query.filter_by(name=dept_name).first()
                    if not existing_dept:
                        dept = Department(name=dept_name, description=dept_desc)
                        db.session.add(dept)
                        print(f"✓ Departamento '{dept_name}' creado")
                    else:
                        print(f"✓ Departamento '{dept_name}' ya existe")

                db.session.commit()
                print("✓ Usuario admin creado: admin/admin123")
                print("✓ Departamentos verificados exitosamente")
            else:
                print("✓ Usuario admin ya existe")
                # Verificar departamentos aunque el admin ya exista
                departments_to_create = [
                    ('IT', 'Departamento de Tecnología'),
                    ('Administración', 'Departamento Administrativo'),
                    ('Recursos Humanos', 'Departamento de RRHH'),
                    ('Finanzas', 'Departamento Financiero')
                ]

                departments_created = False
                for dept_name, dept_desc in departments_to_create:
                    existing_dept = Department.query.filter_by(name=dept_name).first()
                    if not existing_dept:
                        dept = Department(name=dept_name, description=dept_desc)
                        db.session.add(dept)
                        print(f"✓ Departamento '{dept_name}' creado")
                        departments_created = True
                    else:
                        print(f"✓ Departamento '{dept_name}' ya existe")

                if departments_created:
                    db.session.commit()
                    print("✓ Nuevos departamentos creados exitosamente")

            print("🚀 Aplicación iniciando en http://localhost:5000")
            print("📧 Credenciales por defecto: admin / admin123")
            print("⚠️  IMPORTANTE: Cambia la contraseña del admin inmediatamente")

        except Exception as e:
            print(f"❌ Error al inicializar la base de datos: {str(e)}")
            print("Verifica que MySQL esté ejecutándose y que la base de datos 'manuales' exista")
            exit(1)

    # Ejecutar la aplicación en modo desarrollo
    app.run(debug=True, host='0.0.0.0', port=5000)
