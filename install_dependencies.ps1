# Script de PowerShell para instalar dependencias del Password Manager
Write-Host "Instalando dependencias de Python para el Password Manager..." -ForegroundColor Green

# Cambiar al directorio del script
Set-Location -Path $PSScriptRoot

# Verificar si Python está disponible

if (Test-Path $pythonPath) {
    Write-Host "Python encontrado en: $pythonPath" -ForegroundColor Yellow

    # Actualizar pip
    Write-Host "Actualizando pip..." -ForegroundColor Yellow
    & $pythonPath -m pip install --upgrade pip

    # Instalar dependencias
    Write-Host "Instalando dependencias desde requirements.txt..." -ForegroundColor Yellow
    & $pythonPath -m pip install -r requirements.txt

    Write-Host "Dependencias instaladas correctamente." -ForegroundColor Green
} else {
    Write-Host "Error: No se encontró Python en la ruta especificada." -ForegroundColor Red
    Write-Host "Ruta buscada: $pythonPath" -ForegroundColor Red
}

Write-Host "Presiona cualquier tecla para continuar..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
