@echo off
title NetSentinel Platform
cd /d "%~dp0"

echo =========================================================================
echo   Starting NetSentinel Network Security Monitoring (NSM) Platform...
echo =========================================================================

REM Option to rebuild if requested via argument or if JAR is missing
if "%1"=="--build" goto do_build
if "%1"=="rebuild" goto do_build
if "%1"=="-b" goto do_build
if not exist "module-4-backend-storage\target\module-4-backend-storage-1.0.0.jar" goto do_build
goto launch

:do_build
echo [INFO] Packaging project with Maven...
call mvn package -DskipTests
if errorlevel 1 (
    echo [ERROR] Maven build failed. Unable to package application.
    pause
    exit /b 1
)

:launch
echo [INFO] Launching NetSentinel Platform (Java 21+)...
echo [INFO] Web Dashboard will be available at: http://localhost:8080/
echo [INFO] Press Ctrl+C in this terminal window to stop the server.
echo =========================================================================

java -jar "module-4-backend-storage\target\module-4-backend-storage-1.0.0.jar"
if errorlevel 1 (
    echo [ERROR] NetSentinel Platform exited with an error.
)
pause
