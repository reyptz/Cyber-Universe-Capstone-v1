@echo off
echo ========================================
echo Ghost Cyber Universe - Générateur de Clés
echo ========================================
echo.

REM Vérification de Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Python n'est pas installé ou pas dans le PATH
    echo Installez Python 3.11+ depuis https://python.org
    pause
    exit /b 1
)

REM Vérification de pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo pip n'est pas installé
    echo Réinstallez Python avec pip
    pause
    exit /b 1
)

echo Python détecté
echo.

REM Installation des dépendances
echo Installation des dépendances...
pip install -r requirements.txt
if errorlevel 1 (
    echo Erreur lors de l'installation des dépendances
    pause
    exit /b 1
)

echo Dépendances installées
echo.

REM Création des répertoires
echo Création des répertoires...
if not exist "templates" mkdir templates
if not exist "static\css" mkdir static\css
if not exist "static\js" mkdir static\js
if not exist "logs" mkdir logs
if not exist "audit" mkdir audit

echo Répertoires créés
echo.

REM Lancement du serveur
echo Lancement du serveur...
echo.
echo Interface web: http://localhost:8000
echo Documentation API: http://localhost:8000/api/docs
echo Redoc: http://localhost:8000/api/redoc
echo.
echo Appuyez sur Ctrl+C pour arrêter le serveur
echo.

python run.py

pause

