from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField, TextAreaField, URLField, DateTimeField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Email, Length, Optional, URL, EqualTo
from wtforms.widgets import TextArea
from datetime import datetime, timedelta

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember_me = BooleanField('Recordarme')
    two_factor_token = StringField('Código 2FA', validators=[Optional(), Length(min=6, max=6)])

class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8)])
    password_confirm = PasswordField('Confirmar Contraseña',
                                   validators=[DataRequired(), EqualTo('password', message='Las contraseñas deben coincidir')])
    role = SelectField('Rol', choices=[('readonly', 'Solo Lectura'), ('editor', 'Editor'), ('admin', 'Administrador')],
                      default='readonly')
    department_id = SelectField('Departamento', choices=[], coerce=int, validators=[Optional()])

class PasswordEntryForm(FlaskForm):
    name = StringField('Nombre del Recurso', validators=[DataRequired(), Length(max=200)])
    username = StringField('Usuario', validators=[Optional(), Length(max=100)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    password_confirm = PasswordField('Confirmar Contraseña',
                                   validators=[DataRequired(), EqualTo('password', message='Las contraseñas deben coincidir')])
    url = URLField('URL', validators=[Optional(), URL()])
    notes = TextAreaField('Observaciones', validators=[Optional()])
    tags = StringField('Etiquetas (separadas por comas)', validators=[Optional()])
    department_id = SelectField('Departamento', choices=[], coerce=int, validators=[DataRequired()])
    expires_at = DateTimeField('Fecha de Caducidad', validators=[Optional()], format='%Y-%m-%d')

class PasswordEditForm(FlaskForm):
    name = StringField('Nombre del Recurso', validators=[DataRequired(), Length(max=200)])
    username = StringField('Usuario', validators=[Optional(), Length(max=100)])
    password = PasswordField('Nueva Contraseña (dejar vacío para mantener actual)', validators=[Optional()])
    password_confirm = PasswordField('Confirmar Nueva Contraseña',
                                   validators=[Optional(), EqualTo('password', message='Las contraseñas deben coincidir')])
    url = URLField('URL', validators=[Optional(), URL()])
    notes = TextAreaField('Observaciones', validators=[Optional()])
    tags = StringField('Etiquetas (separadas por comas)', validators=[Optional()])
    department_id = SelectField('Departamento', choices=[], coerce=int, validators=[DataRequired()])
    expires_at = DateTimeField('Fecha de Caducidad', validators=[Optional()], format='%Y-%m-%d')
    change_reason = StringField('Motivo del Cambio', validators=[Optional(), Length(max=200)])

class DepartmentForm(FlaskForm):
    name = StringField('Nombre del Departamento', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descripción', validators=[Optional()])

class SearchForm(FlaskForm):
    query = StringField('Buscar', validators=[Optional()])
    department_id = SelectField('Departamento', choices=[('', 'Todos los departamentos')], coerce=str, validators=[Optional()])
    tags = StringField('Etiquetas', validators=[Optional()])
    expired_only = BooleanField('Solo caducadas')

class PasswordGeneratorForm(FlaskForm):
    length = SelectField('Longitud', choices=[(str(i), str(i)) for i in range(8, 65)], default='16', coerce=int)
    include_uppercase = BooleanField('Incluir Mayúsculas', default=True)
    include_lowercase = BooleanField('Incluir Minúsculas', default=True)
    include_numbers = BooleanField('Incluir Números', default=True)
    include_symbols = BooleanField('Incluir Símbolos', default=True)
    exclude_ambiguous = BooleanField('Excluir Caracteres Ambiguos (0, O, l, I)', default=True)

class TwoFactorSetupForm(FlaskForm):
    token = StringField('Código de Verificación', validators=[DataRequired(), Length(min=6, max=6)])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Contraseña Actual', validators=[DataRequired()])
    new_password = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=8)])
    new_password_confirm = PasswordField('Confirmar Nueva Contraseña',
                                       validators=[DataRequired(), EqualTo('new_password', message='Las contraseñas deben coincidir')])

class UserEditForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField('Rol', choices=[('readonly', 'Solo Lectura'), ('editor', 'Editor'), ('admin', 'Administrador')])
    department_id = SelectField('Departamento', choices=[], coerce=int, validators=[Optional()])
    is_active = BooleanField('Usuario Activo', default=True)
    # Agregar campos de contraseña opcionales
    password = PasswordField('Nueva Contraseña (opcional)', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirmar Nueva Contraseña',
                                   validators=[Optional(), EqualTo('password', message='Las contraseñas deben coincidir')])

class ImportForm(FlaskForm):
    csv_file_upload = FileField('Archivo CSV Cifrado', validators=[Optional(), FileAllowed(['enc', 'csv'], 'Solo archivos .enc o .csv')])
    csv_file = TextAreaField('O pega el contenido del archivo aquí', validators=[Optional()], render_kw={"placeholder": "Pega aquí el contenido del archivo CSV cifrado..."})
    department_id = SelectField('Departamento de Destino', choices=[], coerce=int, validators=[DataRequired()])
    encryption_password = PasswordField('Contraseña de Descifrado', validators=[DataRequired()])

    def validate(self, extra_validators=None):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        # Al menos uno de los dos campos debe estar lleno
        if not self.csv_file_upload.data and not self.csv_file.data:
            self.csv_file.errors.append('Debes subir un archivo o pegar el contenido.')
            return False

        return True

class ExportForm(FlaskForm):
    department_id = SelectField('Departamento', choices=[('', 'Todos los departamentos')], coerce=str, validators=[Optional()])
    encryption_password = PasswordField('Contraseña para Cifrar CSV', validators=[DataRequired(), Length(min=8)])
    encryption_password_confirm = PasswordField('Confirmar Contraseña de Cifrado',
                                              validators=[DataRequired(), EqualTo('encryption_password', message='Las contraseñas deben coincidir')])
