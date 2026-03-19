import os
from celery import Celery

# 设置 Django 的默认 settings 模块
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'net_asset_probe.settings')

app = Celery('net_asset_probe')

# 使用字符串让 worker 不用序列化配置对象
app.config_from_object('django.conf:settings', namespace='CELERY')

# 自动发现 task 模块
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
