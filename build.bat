@echo off


echo Packaging...
python src\setup.py bdist_wheel
echo Packaging finished!
pause