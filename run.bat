@echo off
rem Usage: run.bat ^<command^> [arguments]
cd /d "%~dp0"
if not exist out\packet-analyzer.jar call build.bat
java -jar out\packet-analyzer.jar %*
