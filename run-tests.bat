@echo off
rem Compiles main + test code and runs the self-tests.
cd /d "%~dp0"
if exist out\test-classes rmdir /s /q out\test-classes
mkdir out\test-classes
dir /s /b src\main\*.java src\test\*.java > out\test-sources.txt
javac --release 17 -d out\test-classes @out\test-sources.txt || exit /b 1
java -cp out\test-classes com.nishant.packetanalyzer.SelfTest
