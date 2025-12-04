@echo off
chcp 65001 >nul
echo ============================================
echo         TCP 聊天服务器启动
echo ============================================
echo.
python server.py
pause
