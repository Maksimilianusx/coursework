@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "COURSE_DOCKER=%ProgramFiles%\Docker\Docker\resources\bin\docker.exe"
if not exist "%COURSE_DOCKER%" (
  echo Установите Docker Desktop. Подробности настройки находятся в README.md.
  pause
  exit /b 1
)
if not exist "secrets\tls.crt" (
  echo Сначала выполните первоначальную настройку secrets и HTTPS по README.md.
  echo Готовые пароли и закрытые ключи не включаются в архив исходников.
  pause
  exit /b 1
)
"%COURSE_DOCKER%" info >nul 2>&1
if errorlevel 1 (
  echo Запустите Docker Desktop и дождитесь готовности движка, затем повторите запуск.
  pause
  exit /b 1
)
"%COURSE_DOCKER%" compose up -d
if errorlevel 1 (
  echo Запуск не завершен. Проверьте сообщения выше.
  pause
  exit /b 1
)
echo Контейнеры запущены. Первичная готовность Keycloak может занять около минуты.
start "" "https://iam.lab.test/"
endlocal
