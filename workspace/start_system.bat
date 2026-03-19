@echo off
chcp 65001 >nul
title 网络资产探测系统 - 启动器

echo ========================================================
echo       网络资产探测系统 (NetAssetProbe) 一键启动
echo ========================================================
echo.

:: 检查 Python 是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 未检测到 Python，请先安装 Python 3.9+ 并添加到环境变量。
    pause
    exit
)

echo [INFO] 正在检查环境...

:: 提示 Redis
echo.
echo [注意] 请确保 Redis 服务已开启！
echo        如果尚未启动 Redis，任务队列将无法工作。
echo.

:: 启动 Celery Worker
echo [1/3] 正在启动后台扫描节点 (Celery Worker)...
start "NetAssetProbe - Scanner Worker" cmd /k "call venv\Scripts\activate 2>nul & celery -A net_asset_probe worker --pool=solo -l info"

:: 启动 Django Server
echo [2/3] 正在启动 Web 服务 (Django)...
start "NetAssetProbe - Web Server" cmd /k "call venv\Scripts\activate 2>nul & python manage.py runserver 0.0.0.0:8000"

:: 等待服务启动
echo [3/3] 等待服务初始化 (5秒)...
timeout /t 5 >nul

:: 打开浏览器
echo [INFO] 正在打开默认浏览器...
start http://127.0.0.1:8000

echo.
echo ========================================================
echo        系统启动成功！
echo        - Web 服务窗口: 请勿关闭
echo        - 扫描节点窗口: 请勿关闭
echo ========================================================
echo.
pause
