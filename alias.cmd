@echo off

REM Configure Command Prompt to run script on start
reg.exe add "HKCU\Software\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "\"%~0\"" /f >nul

REM Define aliases
doskey ls=dir
