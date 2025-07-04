@echo off
cd /d C:\Snort\bin
snort.exe -c C:\Snort\etc\snort.conf -i 4 -de -l C:\Snort\log