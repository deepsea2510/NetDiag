@echo off
chcp 65001 >nul
title NetDiag 网络诊断工具
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到 Python，请先安装 Python 3.9+ 并加入 PATH
  pause
  exit /b 1
)

echo 正在启动 NetDiag 网络诊断工具...
python main.py
if errorlevel 1 (
  echo.
  echo [提示] 若因 pywebview 组件缺失导致启动失败，可改用浏览器模式：
  echo   python main.py --cli
  pause
)
