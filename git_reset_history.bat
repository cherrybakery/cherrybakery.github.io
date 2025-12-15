setlocal enableextensions enabledelayedexpansion
@echo off

rem https://stackoverflow.com/a/60040042
FOR /F "tokens=3 delims=:" %%L in ("%~0") DO goto :%%L

rem preparing -----------------------------------------------
set working_folder=%cd%
set script_full_path=%~dpnx0 
rem %~dpnx0 same to %~f0 
set script_folder=%~dp0
rem same to %~nx0 
set script_name=%~n0%~x0
set script_name_noext=%~n0

echo The working directory is : %working_folder%
echo(
echo The Fullpath of this batch script is : %script_full_path%
echo(
echo The parent path of this batch script is : %script_folder%

set delay=30
FOR /L %%i IN (1,1,%delay%) DO (
    SET /A remains = %delay% - %%i
    ECHO *******************************WARNING: YOUR REMOTE GITHUB REPO WILL BE WIPED OUT!******************************
    ECHO Start %script_name% in !remains! second, press any key to start
    rem ping 192.0.2.1 -n 1 -w 1000 >nul
    
    @choice /C qwertyuiopasdfghjklzxcvbnm1234567890 /T 1 /D q /N 
    rem echo !errorlevel!
    if not !errorlevel! == 1 goto keypressed
)

:keypressed
    @echo on
    git remote show origin
    echo | set /p ="git remote add origin " >  seturl.bat
    git remote get-url --push origin        >> seturl.bat
    echo.                                   >> seturl.bat
    echo | set /p ="git config user.email " >> seturl.bat
    git config user.email                   >> seturl.bat
    echo.                                   >> seturl.bat
    echo | set /p ="git config user.name "  >> seturl.bat
    git config user.name                    >> seturl.bat
    echo.                                   >> seturl.bat

    rem Clear history on a all branch
    set branch_name=master
    for /f "tokens=* delims=" %%a in ('git branch --show-current') do set branch_name=%%a
    git remote show origin | findstr /c:"HEAD branch:" | for /f "tokens=2 delims=:" %%a in ('more') do set branch_name=%%a
    git remote show origin | findstr /c:"HEAD branch:" | for /f "tokens=2 delims=:" %%a in ('more') do (
        for /f "tokens=*" %%b in ("%%a") do  CALL %~d0\:Foo:\..\%~pn0 %%b
    )
    goto end 

rem the below script run inside for loop call command in another context
:Foo
    set branch_name=%1

:Baa
    rm -rf .git
    git init
    git config core.autocrlf false
    git config gui.encoding utf-8
    git config core.ignorecase false
    call seturl.bat
    git add .
    git commit -m "Initial commit"
    call seturl.bat
    rem rm -f seturl.bat

    git checkout -b %branch_name%
    git branch -a | cut -b 3- | xargs -n 20 git push --delete origin
    git branch -a | cut -b 3- | xargs -n 20 git branch -d
    git push -u --force origin %branch_name%

    rem REMEMBER TO DELETE ANY TAG BECAUSE TAG KEEP ITS OWN HISTORY COMMIT
    for /f "tokens=* delims=" %%a in ('git tag -l') do git push --delete origin %%a

:end
    pause