@echo off
echo 启动 Celery Worker...
celery -A net_asset_probe worker --pool=solo -l info
pause
