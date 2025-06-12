@echo off
echo 🛡️ KPMG-PFCG Pentest Finding Card Generator - Docker Deployment
echo ==============================================================

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Stop any existing containers
echo 🛑 Stopping existing containers...
docker-compose down

REM Build the Docker image
echo 🔨 Building Docker image...
docker-compose build --no-cache

REM Start the container
echo 🚀 Starting KPMG-PFCG container...
docker-compose up -d

REM Wait for container to be ready
echo ⏳ Waiting for container to be ready...
timeout /t 10 /nobreak >nul

REM Check if container is running
docker-compose ps | findstr "Up" >nul
if %errorlevel% equ 0 (
    echo ✅ KPMG-PFCG Pentest Finding Card Generator is now running!
    echo 🌐 Access the application at: http://localhost:1881
    echo.
    echo 📋 Useful commands:
    echo    View logs:     docker-compose logs -f
    echo    Stop service:  docker-compose down
    echo    Restart:       docker-compose restart
    echo.
) else (
    echo ❌ Failed to start container. Check logs with: docker-compose logs
    pause
    exit /b 1
)

pause 