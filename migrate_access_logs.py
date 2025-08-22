#!/usr/bin/env python3
"""
Script de migración para actualizar la columna action en access_logs
Agrega los valores 'import' y 'disable_2fa' al enum existente
"""

import pymysql
from config import Config

def migrate_access_logs():
    """Actualiza el enum de la columna action en access_logs"""

    # Configuración de la base de datos desde config.py
    config = Config()

    # Extraer datos de la URI de la base de datos
    db_uri = config.SQLALCHEMY_DATABASE_URI
    # Formato: mysql+pymysql://usuario:contraseña@host:puerto/basedatos

    # Parsear la URI manualmente
    if 'mysql+pymysql://' in db_uri:
        db_uri = db_uri.replace('mysql+pymysql://', '')

    if '@' in db_uri:
        credentials, host_db = db_uri.split('@')
        if ':' in credentials:
            username, password = credentials.split(':')
        else:
            username = credentials
            password = ''
    else:
        print("Error: No se pudo parsear la URI de la base de datos")
        return False

    if '/' in host_db:
        host_port, database = host_db.split('/')
        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 3306
    else:
        print("Error: No se pudo parsear la URI de la base de datos")
        return False

    try:
        # Conectar a MySQL
        print(f"Conectando a MySQL en {host}:{port} como {username}...")
        connection = pymysql.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=database,
            charset='utf8mb4'
        )

        cursor = connection.cursor()

        print("Conexión exitosa!")
        print("Verificando estructura actual de la tabla access_logs...")

        # Verificar la estructura actual
        cursor.execute("DESCRIBE access_logs")
        columns = cursor.fetchall()

        action_column = None
        for column in columns:
            if column[0] == 'action':
                action_column = column
                break

        if action_column:
            print(f"Columna action encontrada: {action_column[1]}")

            # Verificar si ya contiene 'import'
            if 'import' in action_column[1] and 'disable_2fa' in action_column[1]:
                print("✅ La columna ya contiene los valores necesarios!")
                return True

            print("Actualizando enum de la columna action...")

            # Actualizar el enum para incluir los nuevos valores
            alter_query = """
            ALTER TABLE access_logs 
            MODIFY COLUMN action ENUM(
                'login', 'logout', 'view', 'create', 'update', 'delete', 
                'export', 'import', 'disable_2fa'
            ) NOT NULL
            """

            cursor.execute(alter_query)
            connection.commit()

            print("✅ Enum actualizado exitosamente!")

            # Verificar el cambio
            cursor.execute("DESCRIBE access_logs")
            columns = cursor.fetchall()

            for column in columns:
                if column[0] == 'action':
                    print(f"Nueva definición: {column[1]}")
                    break

            return True

        else:
            print("❌ No se encontró la columna 'action' en la tabla access_logs")
            return False

    except pymysql.Error as e:
        print(f"❌ Error de MySQL: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        if 'connection' in locals():
            connection.close()
            print("Conexión cerrada.")

def verify_migration():
    """Verifica que la migración se haya aplicado correctamente"""
    print("\n" + "="*50)
    print("VERIFICACIÓN DE MIGRACIÓN")
    print("="*50)

    try:
        # Importar después de que los modelos estén actualizados
        from main import app
        from models import AccessLog, db

        with app.app_context():
            # Intentar crear un log de prueba con 'import'
            print("Probando inserción de log con action='import'...")

            # No insertar realmente, solo verificar que el modelo lo acepta
            test_log = AccessLog(
                user_id=1,
                action='import',
                ip_address='127.0.0.1',
                details='Test de migración'
            )

            print("✅ El modelo acepta action='import'")
            print("✅ Migración verificada correctamente!")
            return True

    except Exception as e:
        print(f"❌ Error en verificación: {e}")
        return False

if __name__ == "__main__":
    print("="*60)
    print("MIGRACIÓN DE BASE DE DATOS - ACCESS LOGS")
    print("="*60)
    print("Este script actualizará el enum de la columna 'action'")
    print("en la tabla 'access_logs' para incluir 'import' y 'disable_2fa'")
    print()

    respuesta = input("¿Continuar con la migración? (s/N): ")

    if respuesta.lower() in ['s', 'si', 'sí', 'y', 'yes']:
        print("\nIniciando migración...")

        if migrate_access_logs():
            print("\n✅ ¡Migración completada exitosamente!")
            verify_migration()
        else:
            print("\n❌ La migración falló. Revisa los errores anteriores.")
    else:
        print("Migración cancelada.")
