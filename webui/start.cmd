@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if not errorlevel 1 (
  python serve.py
) else (
  where py >nul 2>nul
  if not errorlevel 1 (
    py -3 serve.py
  ) else (
    echo Python 3 bulunamadi. Python 3 kurup tekrar deneyin.
    pause
  )
)
endlocal
