from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    """用户扩展信息 - 用于RBAC"""
    ROLE_CHOICES = (
        ('ADMIN', '管理员'),
        ('OPERATOR', '操作员'),
        ('VIEWER', '只读用户'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='VIEWER')
    department = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "用户配置"
        verbose_name_plural = "用户配置"

    def __str__(self):
        return f"{self.user.username} - {self.role}"
    
    @property
    def can_scan(self):
        return self.role in ['ADMIN', 'OPERATOR']
    
    @property
    def can_edit(self):
        return self.role in ['ADMIN', 'OPERATOR']
    
    @property
    def can_delete(self):
        return self.role == 'ADMIN'

class Task(models.Model):
    STATUS_CHOICES = (
        ('PENDING', '等待中'),
        ('RUNNING', '进行中'),
        ('COMPLETED', '已完成'),
        ('FAILED', '失败'),
    )
    SCAN_CHOICES = (
        ('quick', '快速扫描'),
        ('normal', '标准扫描'),
        ('deep', '深度扫描'),
        ('service', '服务识别'),
        ('vuln', '漏洞扫描'),
    )
    TCP_SCAN_CHOICES = (
        ('SYN', 'SYN 扫描 (-sS)'),
        ('CONNECT', 'TCP 连接扫描 (-sT)'),
    )
    HOST_DISCOVERY_CHOICES = (
        ('DEFAULT', '默认'),
        ('PING_ONLY', '仅主机发现 (-sn)'),
        ('ICMP', 'ICMP 探测 (-PE -PP)'),
        ('NO_PING', '跳过主机发现 (-Pn)'),
    )
    
    target = models.CharField(max_length=255, help_text="目标 IP 或 域名 (支持网段 e.g. 192.168.1.0/24)", db_index=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_CHOICES, default='quick')
    ports = models.CharField(max_length=100, blank=True, null=True, help_text="端口范围 (如 80,443,8000-9000)。留空按扫描类型默认。")
    enable_tcp = models.BooleanField(default=True)
    enable_udp = models.BooleanField(default=False)
    tcp_scan = models.CharField(max_length=20, choices=TCP_SCAN_CHOICES, default='SYN')
    host_discovery = models.CharField(max_length=20, choices=HOST_DISCOVERY_CHOICES, default='DEFAULT')
    timing = models.IntegerField(default=4, help_text="Nmap timing 模板 (-T0..-T5)")
    
    # 新增高级扫描选项
    use_scripts = models.BooleanField(default=False, verbose_name="启用 NSE 脚本")
    script_categories = models.CharField(max_length=100, blank=True, null=True, 
                                       default='vuln,auth,default', 
                                       help_text="NSE 脚本类别，多个用逗号隔开 (如: vuln,auth,brute)")
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING', db_index=True)
    progress = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    result_summary = models.TextField(blank=True, null=True, help_text="简单的结果摘要")

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.target} - {self.scan_type}"

class ScheduledTask(models.Model):
    """定时扫描任务"""
    INTERVAL_CHOICES = (
        ('MINUTES', '按分钟'),
        ('HOURS', '按小时'),
        ('DAILY', '每天'),
        ('WEEKLY', '每周'),
    )
    STATUS_CHOICES = (
        ('ACTIVE', '启用'),
        ('PAUSED', '暂停'),
    )
    
    name = models.CharField(max_length=100, verbose_name="任务名称")
    target = models.CharField(max_length=255, verbose_name="扫描目标")
    scan_type = models.CharField(max_length=20, choices=Task.SCAN_CHOICES, default='quick')
    ports = models.CharField(max_length=100, blank=True, null=True)
    enable_tcp = models.BooleanField(default=True)
    enable_udp = models.BooleanField(default=False)
    tcp_scan = models.CharField(max_length=20, choices=Task.TCP_SCAN_CHOICES, default='SYN')
    host_discovery = models.CharField(max_length=20, choices=Task.HOST_DISCOVERY_CHOICES, default='DEFAULT')
    timing = models.IntegerField(default=4)
    use_scripts = models.BooleanField(default=False)
    script_categories = models.CharField(max_length=100, blank=True, null=True)
    
    # 调度配置
    interval_type = models.CharField(max_length=20, choices=INTERVAL_CHOICES, default='DAILY')
    interval_value = models.IntegerField(default=1, help_text="间隔值，如每1小时、每2天")
    specific_time = models.TimeField(null=True, blank=True, help_text="指定执行时间 (HH:MM)")
    day_of_week = models.CharField(max_length=20, blank=True, null=True, help_text="周几执行 (1-7逗号分隔)")
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    last_run = models.DateTimeField(null=True, blank=True, verbose_name="上次执行")
    next_run = models.DateTimeField(verbose_name="下次执行")
    created_at = models.DateTimeField(auto_now_add=True)
    total_runs = models.IntegerField(default=0, verbose_name="总执行次数")
    
    class Meta:
        ordering = ['next_run']
        verbose_name = "定时任务"
        verbose_name_plural = "定时任务"

    def __str__(self):
        return f"{self.name} - {self.target}"

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    class Meta:
        verbose_name_plural = "Categories"

    def __str__(self):
        return self.name

class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)
    
    def __str__(self):
        return self.name

class Asset(models.Model):
    IMPORTANCE_CHOICES = (
        (0, '普通'),
        (1, '重要'),
        (2, '关键核心'),
    )
    
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    hostname = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    os_info = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    mac_address = models.CharField(max_length=50, blank=True, null=True, db_index=True)
    vendor = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    is_up = models.BooleanField(default=True, db_index=True)
    last_scanned = models.DateTimeField(auto_now=True, db_index=True)
    open_ports_count = models.IntegerField(default=0)
    
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    tags = models.ManyToManyField(Tag, blank=True)
    importance = models.IntegerField(choices=IMPORTANCE_CHOICES, default=0, db_index=True)
    department = models.CharField(max_length=100, blank=True, null=True, db_index=True, help_text="归属部门")
    business_system = models.CharField(max_length=100, blank=True, null=True, db_index=True, help_text="归属业务系统")
    network_segment = models.CharField(max_length=50, blank=True, null=True, db_index=True, help_text="所属网段 (如 192.168.1.0/24)")
    discovery_method = models.CharField(max_length=20, choices=(
        ('ACTIVE', '主动扫描'),
        ('PASSIVE', '被动探测'),
        ('MANUAL', '手动录入'),
    ), default='ACTIVE')

    def __str__(self):
        return self.ip_address

class Alert(models.Model):
    ALERT_TYPE_CHOICES = (
        ('NEW_ASSET', '陌生设备接入'),
        ('PORT_CHANGE', '非法端口开放'),
        ('VULNERABILITY', '高危漏洞/风险'),
        ('OFFLINE', '设备异常下线'),
        ('SERVICE_CHANGE', '服务变更'),
        ('PROBE', '恶意探测/黑产探针'),
    )
    SEVERITY_CHOICES = (
        ('LOW', '提示'),
        ('MEDIUM', '一般'),
        ('HIGH', '重要'),
        ('CRITICAL', '紧急'),
    )
    STATUS_CHOICES = (
        ('UNREAD', '未读'),
        ('READ', '已读'),
        ('RESOLVED', '已处理'),
        ('IGNORED', '忽略'),
    )
    
    asset = models.ForeignKey(Asset, related_name='alerts', on_delete=models.CASCADE, null=True, blank=True, db_index=True)
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='LOW', db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='UNREAD', db_index=True)
    title = models.CharField(max_length=255)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.get_alert_type_display()}] {self.title}"

class AssetChangeLog(models.Model):
    asset = models.ForeignKey(Asset, related_name='change_logs', on_delete=models.CASCADE)
    change_type = models.CharField(max_length=50) # 新增资产, 端口变化, OS变更, 下线
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']

class PassiveEvent(models.Model):
    EVENT_TYPE_CHOICES = (
        ('DNS', 'DNS'),
        ('HTTP', 'HTTP'),
        ('TLS', 'TLS'),
        ('LOG', 'LOG'),
    )
    asset = models.ForeignKey(Asset, related_name='passive_events', on_delete=models.CASCADE, null=True, blank=True)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPE_CHOICES)
    source = models.CharField(max_length=100, blank=True, null=True)
    src_ip = models.GenericIPAddressField(blank=True, null=True)
    dst_ip = models.GenericIPAddressField(blank=True, null=True)
    src_port = models.IntegerField(blank=True, null=True)
    dst_port = models.IntegerField(blank=True, null=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    url = models.TextField(blank=True, null=True)
    method = models.CharField(max_length=20, blank=True, null=True)
    status_code = models.IntegerField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    raw = models.TextField(blank=True, null=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    count = models.IntegerField(default=1)

    class Meta:
        ordering = ['-last_seen']

    def __str__(self):
        return f"{self.event_type} {self.hostname or self.url or ''}".strip()

class Port(models.Model):
    asset = models.ForeignKey(Asset, related_name='ports', on_delete=models.CASCADE)
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    service_name = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=200, blank=True)
    state = models.CharField(max_length=20) # open, closed, filtered
    banner = models.TextField(blank=True, null=True)
    app_fingerprint = models.CharField(max_length=200, blank=True, null=True, help_text="应用指纹 (如 Nginx/1.18.0, Tomcat/9.0.31)")
    is_vulnerable_version = models.BooleanField(default=False, help_text="是否为高风险/老旧版本")
    
    class Meta:
        unique_together = ('asset', 'port_number', 'protocol')
        ordering = ['port_number']

    def __str__(self):
        return f"{self.port_number}/{self.protocol} {self.service_name}"

class Report(models.Model):
    """扫描报告"""
    REPORT_TYPE_CHOICES = (
        ('TASK', '任务报告'),
        ('SCHEDULED', '定时任务报告'),
        ('ASSET', '资产报告'),
    )
    FORMAT_CHOICES = (
        ('HTML', 'HTML'),
        ('JSON', 'JSON'),
        ('CSV', 'CSV'),
    )
    
    name = models.CharField(max_length=200, verbose_name="报告名称")
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, default='TASK')
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default='HTML')
    
    target = models.CharField(max_length=255, blank=True, null=True, verbose_name="扫描目标")
    task = models.ForeignKey('Task', related_name='reports', on_delete=models.CASCADE, null=True, blank=True)
    scheduled_task = models.ForeignKey(ScheduledTask, related_name='reports', on_delete=models.CASCADE, null=True, blank=True)
    
    asset_count = models.IntegerField(default=0, verbose_name="资产数量")
    vuln_count = models.IntegerField(default=0, verbose_name="漏洞数量")
    high_vuln_count = models.IntegerField(default=0, verbose_name="高危漏洞数")
    medium_vuln_count = models.IntegerField(default=0, verbose_name="中危漏洞数")
    low_vuln_count = models.IntegerField(default=0, verbose_name="低危漏洞数")
    
    summary = models.TextField(blank=True, verbose_name="摘要")
    content = models.JSONField(default=dict, verbose_name="报告内容")
    
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    file_path = models.CharField(max_length=500, blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "扫描报告"
        verbose_name_plural = "扫描报告"

    def __str__(self):
        return f"{self.name} - {self.created_at|date:'Y-m-d H:i'}"

class Vulnerability(models.Model):
    asset = models.ForeignKey(Asset, related_name='vulns', on_delete=models.CASCADE)
    port = models.ForeignKey(Port, related_name='vulns', on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=(
        ('LOW', '低危'),
        ('MEDIUM', '中危'),
        ('HIGH', '高危'),
        ('CRITICAL', '严重'),
    ), default='LOW')
    solution = models.TextField(blank=True)
    cve_id = models.CharField(max_length=50, blank=True, null=True)
    
    def __str__(self):
        return self.name
