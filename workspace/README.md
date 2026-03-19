# 基于Django的局域网网络资产探测系统

## 一、项目概述

本系统是一个功能完备的局域网网络资产探测与安全管理平台，采用B/S架构，基于Django Web框架开发，集成了Nmap网络扫描引擎，实现了网络资产的自动发现、信息采集、状态监控、风险告警及可视化管理。

### 1.1 系统功能

| 模块 | 功能描述 |
|------|----------|
| 扫描任务管理 | 创建和管理主动扫描任务，支持配置扫描参数 |
| 定时任务管理 | 周期性自动扫描，自动执行任务 |
| 资产台账管理 | 集中管理网络资产信息，多维度筛选 |
| 网络拓扑 | ECharts可视化展示资产分布 |
| 被动探测 | 基于Scapy流量嗅探发现内网资产 |
| 告警管理 | 风险告警、状态通知 |
| 数据可视化 | TOP排名分析、统计分析图表 |

---

## 二、技术架构

### 2.1 技术栈

```
┌─────────────────────────────────────────────────────────┐
│                    前端技术                             │
│  Bootstrap 5  │  ECharts  │  Font Awesome  │ jQuery   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    后端技术                             │
│         Django 6.0  │  Celery  │  Python 3.13          │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    数据存储                             │
│         SQLite  │  Django ORM                          │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    探测引擎                             │
│         Nmap  │  Scapy  │  多线程扫描                   │
└─────────────────────────────────────────────────────────┘
```

### 2.2 架构模式

系统采用 **MVT（Model-View-Template）** 架构模式：

| 层次 | 文件 | 职责 |
|------|------|------|
| **Model** | `scanner/models.py` | 数据模型定义，数据库交互 |
| **View** | `scanner/views.py` | 业务逻辑处理，请求响应 |
| **Template** | `scanner/templates/` | 前端页面渲染 |

### 2.3 项目结构

```
net_asset_probe/
├── db.sqlite3                  # SQLite数据库
├── manage.py                   # Django管理脚本
├── requirements.txt            # Python依赖
├── net_asset_probe/           # 项目配置目录
│   ├── __init__.py
│   ├── settings.py            # Django配置文件
│   ├── urls.py                # 项目路由配置
│   └── wsgi.py                # WSGI入口
├── scanner/                   # 应用目录
│   ├── __init__.py
│   ├── admin.py               # Django后台管理
│   ├── apps.py                # 应用配置
│   ├── context_processors.py  # 上下文处理器
│   ├── forms.py               # 表单定义
│   ├── migrations/            # 数据库迁移
│   ├── models.py              # 数据模型 ★
│   ├── tasks.py               # Celery任务 ★
│   ├── urls.py                # 应用路由 ★
│   ├── utils/                 # 工具模块
│   │   ├── nmap_scanner.py    # Nmap扫描封装 ★
│   │   ├── notification.py    # 通知模块
│   │   └── traffic_sniffer.py # 流量嗅探 ★
│   ├── views.py               # 视图函数 ★
│   └── templates/scanner/      # 模板目录
│       ├── base.html           # 基础模板
│       ├── dashboard.html     # 首页仪表盘
│       ├── task_form.html     # 扫描任务表单
│       ├── asset_list.html    # 资产列表
│       ├── topology.html      # 网络拓扑
│       └── ...
└── scanner/management/commands/
    ├── run_scheduler.py        # 定时任务调度器 ★
    └── passive_sniffer.py      # 被动探测命令
```

---

## 三、核心模块实现

### 3.1 扫描任务模块

**文件**: `scanner/views.py`, `scanner/tasks.py`, `scanner/utils/nmap_scanner.py`

**实现原理**:
1. 用户通过表单提交扫描参数（目标IP、端口范围、扫描类型等）
2. Django视图创建Task对象，状态设为PENDING
3. Celery异步任务调用`run_scan()`函数执行扫描
4. NmapScanner类封装nmap命令执行和结果解析
5. 扫描结果解析后更新Asset、Port等数据表

**关键代码**:
```python
# scanner/tasks.py
@shared_task(bind=True)
def run_scan(self, task_id):
    task = Task.objects.get(id=task_id)
    scanner = NmapScanner()
    results = scanner.scan(
        target=task.target,
        ports=task.ports,
        scan_type=task.scan_type,
        timing=task.timing
    )
    # 解析结果并更新资产
    for host in results:
        asset, _ = Asset.objects.update_or_create(
            ip=host['ip'],
            defaults={'hostname': host.get('hostname')}
        )
```

### 3.2 定时任务模块

**文件**: `scanner/models.py` (ScheduledTask), `scanner/management/commands/run_scheduler.py`

**实现原理**:
1. 用户创建ScheduledTask对象，配置扫描参数和执行周期
2. 系统计算下次执行时间next_run并保存
3. run_scheduler命令每60秒检查一次待执行任务
4. 发现到期的任务则创建对应扫描任务
5. 更新last_run、total_runs、next_run字段

**调度周期支持**:
```python
# 按分钟/小时/天/周执行
if task.interval_type == 'MINUTES':
    return now + timedelta(minutes=task.interval_value)
elif task.interval_type == 'HOURS':
    return now + timedelta(hours=task.interval_value)
elif task.interval_type == 'DAILY':
    return now + timedelta(days=task.interval_value)
elif task.interval_type == 'WEEKLY':
    return now + timedelta(weeks=1)
```

### 3.3 资产台账模块

**文件**: `scanner/models.py` (Asset), `scanner/views.py` (AssetListView)

**数据模型**:
```python
class Asset(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    vendor = models.CharField(max_length=100, blank=True)  # 厂商识别
    os_info = models.CharField(max_length=200, blank=True)  # 操作系统
    os_accuracy = models.IntegerField(default=0)  # 识别准确度
    status = models.CharField(max_length=20, default='UNKNOWN')
    network_segment = models.CharField(max_length=50, blank=True)
    importance = models.CharField(max_length=20, default='NORMAL')
    business = models.ForeignKey('Category', on_delete=models.SET_NULL, null=True)
    last_scanned = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
```

**列表查询优化**:
- 使用select_related减少数据库查询
- 分页处理（paginate_by = 50）
- 支持多维度筛选（IP、状态、厂商等）

### 3.4 网络拓扑模块

**文件**: `scanner/views.py` (TopologyView), `scanner/templates/scanner/topology.html`

**实现原理**:
1. 查询所有在线资产作为节点
2. 根据端口信息分析资产间的关联关系作为边
3. 使用ECharts的Graph类型绘制拓扑图
4. 支持节点点击查看详情、缩放拖拽等交互

**ECharts配置**:
```javascript
var topologyChart = echarts.init(document.getElementById('topologyChart'));
topologyChart.setOption({
    type: 'graph',
    layout: 'force',
    nodes: nodes,  // 资产节点
    links: links,  // 关联关系
    roam: true,
    label: { show: true, position: 'right' }
});
```

### 3.5 被动探测模块

**文件**: `scanner/utils/traffic_sniffer.py`

**实现原理**:
1. 使用Scapy库监听网络接口
2. 捕获ARP报文，提取源IP和MAC
3. 根据MAC地址前缀识别厂商信息
4. 自动创建或更新Asset记录

**核心代码**:
```python
def sniff_arp(interface='eth0'):
    def process_packet(pkt):
        if pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            vendor = get_vendor_by_mac(mac)
            Asset.objects.update_or_create(
                ip=ip,
                defaults={'mac_address': mac, 'vendor': vendor}
            )
    sniff(iface=interface, prn=process_packet, filter='arp')
```

### 3.6 告警管理模块

**文件**: `scanner/models.py` (Alert), `scanner/views.py`

**告警类型**:
- NEW_ASSET: 新资产发现
- ASSET_CHANGE: 资产信息变更
- ASSET_OFFLINE: 资产离线
- VULN_DETECTED: 发现漏洞

**状态流转**: UNREAD → READ → RESOLVED

---

## 四、数据库设计

### 4.1 核心数据表

| 表名 | 说明 | 主要字段 |
|------|------|----------|
| scanner_task | 扫描任务 | target, scan_type, status, progress |
| scanner_asset | 网络资产 | ip, hostname, mac_address, vendor, os_info |
| scanner_port | 端口信息 | asset(FK), port_number, protocol, service |
| scanner_vulnerability | 漏洞信息 | asset(FK), name, severity |
| scanner_scheduledtask | 定时任务 | name, target, interval_type, next_run |
| scanner_alert | 告警信息 | type, status, asset(FK), message |
| scanner_category | 业务系统 | name, description |
| scanner_passiveevent | 被动事件 | ip, mac, vendor, timestamp |

### 4.2 关联关系

```
Task 1 --> N Asset (通过扫描发现)
Asset 1 --> N Port
Asset 1 --> N Vulnerability
Asset N --> 1 Category (业务系统)
Asset 1 --> N Alert
ScheduledTask 1 --> N Task (定时创建)
```

---

## 五、API接口

### 5.1 主要URL路由

| 路径 | 视图 | 说明 |
|------|------|------|
| `/` | DashboardView | 首页仪表盘 |
| `/tasks/` | TaskListView | 扫描任务列表 |
| `/tasks/create/` | TaskCreateView | 创建扫描任务 |
| `/scheduled/` | ScheduledTaskListView | 定时任务列表 |
| `/assets/` | AssetListView | 资产台账 |
| `/assets/<id>/` | AssetDetailView | 资产详情 |
| `/topology/` | TopologyView | 网络拓扑 |
| `/passive/` | PassiveEventListView | 被动事件 |
| `/alerts/` | AlertListView | 告警列表 |
| `/api/tasks/status/` | api_task_status | 任务状态API |

---

## 六、关键技术亮点

### 6.1 扫描效率优化

- **多线程并行扫描**: Python threading模块并发处理多个主机
- **Timing模板配置**: 支持T1-T5扫描速度调节
- **智能主机发现**: 根据网络环境选择最优发现策略

### 6.2 数据准确性保障

- **准确度阈值**: OS识别准确率≥80%才更新操作系统信息
- **MAC厂商库**: 根据MAC前缀识别设备厂商
- **增量扫描**: 避免重复探测，只扫描变化部分

### 6.3 可视化展示

- **ECharts集成**: 柱状图、饼图、折线图、关系图
- **TOP排名**: TOP10资产/端口/厂商/业务系统
- **响应式布局**: Bootstrap适配不同屏幕尺寸

### 6.4 定时任务可靠性

- **独立调度器**: run_scheduler命令持续运行
- **状态检查**: 每次执行前检查任务状态
- **自动重试**: 扫描失败自动记录日志

---

## 七、系统运行

### 7.1 环境要求

- Python 3.8+
- Django 6.0
- Nmap (需安装到系统)
- Redis (用于Celery)
- Scapy (用于被动探测)

### 7.2 启动命令

```bash
# 安装依赖
pip install -r requirements.txt

# 数据库迁移
python manage.py migrate

# 启动Django开发服务器
python manage.py runserver 127.0.0.1:8000

# 启动定时任务调度器 (单独终端)
python manage.py run_scheduler

# 启动被动探测 (单独终端)
python manage.py passive_sniffer
```

---

## 八、总结

本系统综合运用了Django Web开发、Nmap网络扫描、Celery异步任务、Scapy流量嗅探、ECharts可视化等技术，实现了局域网网络资产的自动发现、动态管理和可视化分析。系统采用模块化设计，各功能模块职责清晰，便于后续扩展和维护。
