@echo off
REM Falcon Quick Update Script for Windows
REM Simple script to update Falcon using git

echo.
echo 🦅 Falcon Quick Update
echo ======================
echo.

REM Check if we're in the right directory
if not exist "main.py" (
    echo ❌ Error: Not in Falcon directory
    echo 💡 Please run this script from the Falcon directory
    pause
    exit /b 1
)

REM Check if git is available
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Git is not installed
    echo 💡 Please install Git to use this update script
    pause
    exit /b 1
)

REM Check if we're in a git repository
if not exist ".git" (
    echo ❌ Error: Not a git repository
    echo 💡 Clone Falcon using: git clone https://github.com/dharmraj8033/Falcon.git
    pause
    exit /b 1
)

echo [INFO] Checking for updates...

REM Fetch latest changes
git fetch origin

REM Check if updates are available
for /f %%i in ('git rev-list --count HEAD..origin/main') do set COMMITS_BEHIND=%%i

if "%COMMITS_BEHIND%"=="0" (
    echo ✅ Falcon is already up to date!
    pause
    exit /b 0
)

echo 🎉 %COMMITS_BEHIND% new commits available!

REM Ask user if they want to update
set /p UPDATE="🤔 Update now? (y/N): "
if /i not "%UPDATE%"=="y" (
    echo ⏭️ Update cancelled
    pause
    exit /b 0
)

echo [INFO] Updating Falcon...

REM Pull latest changes
git pull origin main
if %errorlevel% equ 0 (
    echo ✅ Successfully updated Falcon!
    
    REM Update Python dependencies
    echo [INFO] Updating dependencies...
    python -m pip install -r requirements.txt
    if %errorlevel% equ 0 (
        echo ✅ Dependencies updated!
    ) else (
        echo ⚠️  Some dependencies may need manual update
    )
    
    echo 🎉 Update completed successfully!
    echo 💡 Restart any running Falcon instances to use the latest version
) else (
    echo ❌ Update failed!
    echo 💡 You may need to resolve conflicts manually
)

pause
