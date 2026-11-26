@echo off
rem Compiles the project and creates out\packet-analyzer.jar  (needs a JDK 17 or newer)
cd /d "%~dp0"
if exist out rmdir /s /q out
mkdir out\classes
dir /s /b src\main\*.java > out\sources.txt
javac --release 17 -d out\classes @out\sources.txt || exit /b 1
echo Main-Class: com.nishant.packetanalyzer.Main> out\manifest.txt
jar cfm out\packet-analyzer.jar out\manifest.txt -C out\classes . || exit /b 1
echo Built out\packet-analyzer.jar
