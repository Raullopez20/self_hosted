import pymysql
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

DB_HOST = os.getenv('DB_HOST', '')
DB_PORT = int(os.getenv('DB_PORT', ))
DB_NAME = os.getenv('DB_NAME', '')
DB_USER = os.getenv('DB_USER', '')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')

print(f"Probando conexión a MySQL:")
print(f"Host: {DB_HOST}")
print(f"Puerto: {DB_PORT}")
print(f"Base de datos: {DB_NAME}")
print(f"Usuario: {DB_USER}")
print("-" * 50)

try:
    # Probar conexión
    connection = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    print("✓ Conexión exitosa a MySQL")

    cursor = connection.cursor()
    cursor.execute("SELECT 1")
    result = cursor.fetchone()
    print("✓ Query de prueba ejecutada correctamente")

    # Verificar tablas existentes
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    print(f"\nTablas en la base de datos '{DB_NAME}':")
    if tables:
        for table in tables:
            print(f"  - {table[0]}")
    else:
        print("  (No hay tablas - esto es normal para una nueva instalación)")

    connection.close()
    print("\n🎉 La conexión funciona correctamente")
    print("La aplicación puede proceder a crear las tablas")

except pymysql.err.OperationalError as e:
    error_code, error_message = e.args
    print(f"❌ Error de conexión ({error_code}): {error_message}")

    if error_code == 1045:
        print("\n💡 Solución:")
        print("Ejecuta estos comandos en el servidor MySQL:")
        print(f"CREATE USER '{DB_USER}'@'%' IDENTIFIED BY '{DB_PASSWORD}';")
        print(f"GRANT ALL PRIVILEGES ON {DB_NAME}.* TO '{DB_USER}'@'%';")
        print("FLUSH PRIVILEGES;")

except Exception as e:
    print(f"❌ Error: {str(e)}")
