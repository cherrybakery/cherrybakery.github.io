@echo off
setlocal enabledelayedexpansion

:: Set size limit: 45MB = 47185920 bytes
set "LIMIT=47185920"
set "FOUND=0"

echo [INFO] Checking Git-tracked changed files larger than 45MB...

:: Get list of files that would be committed
for /f "delims=" %%f in ('git diff --cached --name-only') do (
    if exist "%%f" (
        for %%A in ("%%f") do (
            set "size=%%~zA"
            if !size! gtr %LIMIT% (
                echo [LARGE] %%f (!size! bytes)
                set "FOUND=1"
            )
        )
    )
)

if "%FOUND%"=="1" (
    echo [ERROR] One or more staged files exceed 45MB. Commit aborted.
    exit /b 1
)

echo [OK] No large files staged for commit.









for /f %%b in ('git rev-parse --abbrev-ref HEAD') do (
    git fetch origin
    git reset --mixed origin/%%b
)

git pull
git add -A 
git commit -am "." 
rem git push -f
git push -f -u origin --all
pause