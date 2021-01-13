@echo off
setlocal enabledelayedexpansion
set "files="
for /f "delims=" %%a in ('dir /b /a-d "%*" ') do (
	set "files=%%a"
	@echo -----
	@echo Checked file: %%a
	x509lint.exe "%%a"
)
