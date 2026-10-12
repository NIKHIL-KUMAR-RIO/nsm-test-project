@echo off
title NetSentinel Platform
cd /d "%~dp0"

echo =========================================================================
echo   Starting NetSentinel Network Security Monitoring (NSM) Platform...
echo =========================================================================

REM Check if Fat JAR exists, build if missing
if not exist "module-4-backend-storage\target\module-4-backend-storage-1.0.0.jar" (
    echo [INFO] Executable Fat JAR not found. Building project with Maven...
    call mvn package -DskipTests
    if errorlevel 1 (
        echo [ERROR] Maven build failed. Unable to package application.
        pause
        exit /b 1
    )
)

echo [INFO] Launching NetSentinel Platform (Java 21+)...
echo [INFO] Web Dashboard will be available at: http://localhost:8080/
echo [INFO] Press Ctrl+C in this terminal window to stop the server.
echo =========================================================================

java -jar "module-4-backend-storage\target\module-4-backend-storage-1.0.0.jar"
if errorlevel 1 (
    echo [ERROR] NetSentinel Platform exited with an error.
)
pause
