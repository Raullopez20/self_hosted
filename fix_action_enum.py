#!/usr/bin/env python3
"""
Script para corregir el enum de la columna 'action' en access_logs
Añade los valores faltantes sin perder datos existentes
"""

import pymysql
from config import Config

def fix_action_enum():
    """Actualiza el enum de la columna action para incluir todos los valores necesarios"""

    # Configuración de conexión
    config = Config()

    # Extraer parámetros de la URL de la base de datos
    db_url = config.SQLALCHEMY_DATABASE_URI
    if db_url.startswith('mysql+pymysql://'):
        # Formato: mysql+pymysql://user:password@host:port/database
        db_url = db_url[15:]  # Remover 'mysql+pymysql://'

        if '@' in db_url:
            auth_part, host_db_part = db_url.split('@', 1)
            if ':' in auth_part:
                username, password = auth_part.split(':', 1)
            else:
                username = auth_part
                password = ''

            if '/' in host_db_part:
                host_port, database = host_db_part.split('/', 1)
                if ':' in host_port:
                    host, port = host_port.split(':')
                    port = int(port)
                else:
                    host = host_port
                    port = 3306
            else:
                host = host_db_part
                port = 3306
                database = ''
        else:
            print("Error: No se pudo parsear la URL de la base de datos")
            return False
    else:
        print("Error: URL de base de datos no soportada")
        return False

    try:
        # Conectar a la base de datos
        connection = pymysql.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=database,
            charset='utf8mb4'
        )

        with connection.cursor() as cursor:
            print("Conectado a la base de datos exitosamente")

            # Verificar la estructura actual de la tabla
            cursor.execute("DESCRIBE access_logs")
            columns = cursor.fetchall()

            print("\nEstructura actual de access_logs:")
            for column in columns:
                print(f"  {column}")

            # Verificar los valores enum actuales
            cursor.execute("""
                SELECT COLUMN_TYPE 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'access_logs' 
                AND COLUMN_NAME = 'action'
            """, (database,))

            current_enum = cursor.fetchone()
            if current_enum:
                print(f"\nEnum actual de 'action': {current_enum[0]}")

            # Modificar la columna para incluir todos los valores necesarios
            print("\nActualizando la columna 'action'...")

            alter_query = """
                ALTER TABLE access_logs 
                MODIFY COLUMN action ENUM(
                    'login', 'logout', 'view', 'create', 'update', 
                    'delete', 'export', 'import', 'disable_2fa'
                ) NOT NULL
            """

            cursor.execute(alter_query)
            connection.commit()

            print("✅ Columna 'action' actualizada exitosamente")

            # Verificar la nueva estructura
            cursor.execute("""
                SELECT COLUMN_TYPE 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'access_logs' 
                AND COLUMN_NAME = 'action'
            """, (database,))

            new_enum = cursor.fetchone()
            if new_enum:
                print(f"Nuevo enum de 'action': {new_enum[0]}")

            # Probar inserción de un registro con 'import'
            print("\nProbando inserción de registro con action='import'...")

            test_query = """
                INSERT INTO access_logs (user_id, action, ip_address, details, timestamp) 
                VALUES (1, 'import', '127.0.0.1', 'Test import action', NOW())
            """

            cursor.execute(test_query)
            connection.commit()

            # Verificar que se insertó correctamente
            cursor.execute("SELECT * FROM access_logs WHERE action = 'import' ORDER BY id DESC LIMIT 1")
            test_record = cursor.fetchone()

            if test_record:
                print("✅ Test de inserción exitoso")
                print(f"Registro insertado: {test_record}")

                # Limpiar el registro de prueba
                cursor.execute("DELETE FROM access_logs WHERE id = %s", (test_record[0],))
                connection.commit()
                print("🧹 Registro de prueba eliminado")
            else:
                print("❌ Error en el test de inserción")

        connection.close()
        print("\n✅ Corrección completada exitosamente")
        return True

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔧 Iniciando corrección del enum 'action' en access_logs...")
    print("=" * 60)

    success = fix_action_enum()

    print("=" * 60)
    if success:
        print("✅ Proceso completado exitosamente")
        print("Ya puedes usar la función de importar sin errores")
    else:
        print("❌ Proceso fallido")
        print("Revisa los errores mostrados arriba")
