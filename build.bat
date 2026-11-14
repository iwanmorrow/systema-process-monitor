@echo off
setlocal
cd /d "%~dp0"

python -m venv .venv 2>nul
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

REM --uac-admin: подписка на WMI process trace (Win32_ProcessStartTrace /
REM StopTrace) требует повышенных прав; без них приложение работает, но на
REM polling (это видно в статус-баре).
REM Пакет windows/ импортируется лениво (только на win32), поэтому его модули
REM и pywin32-зависимости перечислены явно.
REM ВНИМАНИЕ: сборка не проверялась на реальной Windows (см. README).
pyinstaller --noconfirm --clean ^
  --onefile ^
  --windowed ^
  --uac-admin ^
  --name "SystemaProcesses" ^
  --hidden-import windows.wmi_events ^
  --hidden-import windows.signature ^
  --hidden-import win32com.client ^
  --hidden-import win32timezone ^
  --hidden-import pythoncom ^
  --hidden-import win32api ^
  app.py

echo.
echo Готово: dist\SystemaProcesses.exe
echo Запускайте от имени администратора, чтобы включился event-driven backend.
pause
