@echo off
setlocal enabledelayedexpansion


echo Packaging...
python setup.py bdist_wheel

for /D %%G in ("%~dp0\*") do (
    set "folderName=%%~nxG"
    if "!folderName:~-9!"==".egg-info" (
        rmdir /s /q "%%G"
    )
)
rmdir /s /q "build"

echo Packaging finished!
pause
