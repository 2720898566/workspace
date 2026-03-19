from django.views.generic import ListView, DetailView, CreateView, UpdateView, TemplateView
from django.views.generic.edit import FormMixin
from django.urls import reverse_lazy, reverse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.contrib import messages
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.db.models import Count, Q, Value
from django.db.models.functions import Coalesce
import re
import csv
import json
import ipaddress
import threading

from django.utils import timezone

from .models import Task, Asset, Port, Vulnerability, AssetChangeLog, Alert, PassiveEvent, Category, Report, ScheduledTask
from .tasks import run_scan
from .utils.passive_ingest import ingest_event, validate_ingest_token
from .utils.traffic_sniffer import start_passive_monitoring, stop_passive_monitoring, get_sniffer_status

class DashboardView(TemplateView):
    template_name = 'scanner/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from django.conf import settings
        context['total_assets'] = Asset.objects.count()
        context['total_tasks'] = Task.objects.count()
        context['total_vulns'] = Vulnerability.objects.count()
        context['recent_tasks'] = Task.objects.order_by('-created_at')[:5]
        context['high_risk_vulns'] = Vulnerability.objects.filter(severity__in=['HIGH', 'CRITICAL']).count()
        
        # 统计数据用于图表
        os_stats = Asset.objects.annotate(
            os=Coalesce('os_info', Value('Unknown'))
        ).exclude(os='').values('os').annotate(count=Count('os')).order_by('-count')
        
        os_list = []
        unknown_os_count = 0
        for item in os_stats:
            if item['os'] == 'Unknown' or item['os'] is None:
                unknown_os_count += item['count']
            else:
                os_list.append({'os_info': item['os'], 'count': item['count']})
        
        if unknown_os_count > 0:
            os_list.append({'os_info': 'Unknown', 'count': unknown_os_count})
        
        context['os_stats'] = os_list[:10]
        
        cat_stats = Asset.objects.annotate(
            cat_name=Coalesce('category__name', Value('Uncategorized'))
        ).values('cat_name').annotate(count=Count('cat_name')).order_by('-count')
        
        cat_list = []
        unknown_cat_count = 0
        for item in cat_stats:
            if item['cat_name'] == 'Uncategorized' or item['cat_name'] is None:
                unknown_cat_count += item['count']
            else:
                cat_list.append({'category__name': item['cat_name'], 'count': item['count']})
        
        if unknown_cat_count > 0:
            cat_list.append({'category__name': 'Uncategorized', 'count': unknown_cat_count})
        
        context['cat_stats'] = cat_list
        
        service_stats = Port.objects.annotate(
            service=Coalesce('service_name', Value('Unknown'))
        ).exclude(service='').values('service').annotate(count=Count('service')).order_by('-count')[:10]
        
        stats_list = []
        unknown_count = 0
        for item in service_stats:
            if item['service'] == 'Unknown' or item['service'] is None:
                unknown_count += item['count']
            else:
                stats_list.append({'service_name': item['service'], 'count': item['count']})
        
        if unknown_count > 0:
            stats_list.append({'service_name': 'Unknown', 'count': unknown_count})
        
        context['service_stats'] = stats_list
        
        # 最近变更
        context['recent_changes'] = AssetChangeLog.objects.order_by('-timestamp')[:10]
        
        # 统计告警
        context['recent_alerts'] = Alert.objects.filter(status='UNREAD').order_by('-timestamp')[:5]
        
        # 网段统计
        net_stats = Asset.objects.annotate(
            segment=Coalesce('network_segment', Value('Unknown'))
        ).exclude(segment='').values('segment').annotate(count=Count('segment')).order_by('-count')
        
        net_list = []
        unknown_net_count = 0
        for item in net_stats:
            if item['segment'] == 'Unknown' or item['segment'] is None:
                unknown_net_count += item['count']
            else:
                net_list.append({'network_segment': item['segment'], 'count': item['count']})
        
        if unknown_net_count > 0:
            net_list.append({'network_segment': 'Unknown', 'count': unknown_net_count})
        
        context['net_stats'] = net_list[:10]
        
        # 实时状态统计
        from django.utils import timezone
        from datetime import timedelta
        today = timezone.now().date()
        context['online_assets'] = Asset.objects.filter(is_up=True).count()
        context['new_assets_today'] = AssetChangeLog.objects.filter(change_type='新增资产', timestamp__date=today).count()
        context['abnormal_assets'] = Alert.objects.filter(alert_type='OFFLINE', status='UNREAD').count()
        
        # 风险趋势 (最近7天)
        trend_data = []
        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            count = Vulnerability.objects.filter(asset__last_scanned__date__lte=day).count() # 简单模拟趋势
            trend_data.append({'day': day.strftime('%m-%d'), 'count': count})
        context['risk_trend'] = trend_data
        
        # 被动探测统计
        context['passive_stats'] = PassiveEvent.objects.values('event_type').annotate(count=Count('id')).order_by('-count')
        
        # TOP 统计
        # TOP 10 高危资产
        top_vuln_assets = Asset.objects.annotate(
            vuln_count=Count('vulns')
        ).filter(vuln_count__gt=0).order_by('-vuln_count')[:10]
        context['top_vuln_assets'] = [
            {'ip': a.ip_address, 'hostname': a.hostname, 'count': a.vuln_count}
            for a in top_vuln_assets
        ]
        
        # TOP 10 开放端口
        port_stats = Port.objects.values('port_number').annotate(
            count=Count('asset')
        ).order_by('-count')[:10]
        context['top_ports'] = list(port_stats)
        
        # TOP 10 厂商
        vendor_stats = Asset.objects.annotate(
            v=Coalesce('vendor', Value('Unknown'))
        ).exclude(v='').values('v').annotate(count=Count('id')).order_by('-count')[:10]
        context['top_vendors'] = [
            {'vendor': item['v'], 'count': item['count']}
            for item in vendor_stats
        ]
        
        # TOP 10 操作系统
        os_top = Asset.objects.annotate(
            o=Coalesce('os_info', Value('Unknown'))
        ).exclude(o='').values('o').annotate(count=Count('id')).order_by('-count')[:10]
        context['top_os'] = [
            {'os': item['o'], 'count': item['count']}
            for item in os_top
        ]
        
        # TOP 10 业务系统
        biz_stats = Asset.objects.annotate(
            b=Coalesce('business_system', Value('Unknown'))
        ).exclude(b='').values('b').annotate(count=Count('id')).order_by('-count')[:10]
        context['top_business'] = [
            {'business': item['b'], 'count': item['count']}
            for item in biz_stats
        ]
        
        # 风险评分计算
        high_vuln = Vulnerability.objects.filter(severity__in=['HIGH', 'CRITICAL']).count()
        medium_vuln = Vulnerability.objects.filter(severity='MEDIUM').count()
        total_vuln = Vulnerability.objects.count()
        total_assets = Asset.objects.count()
        
        if total_assets > 0:
            risk_score = min(100, (high_vuln * 10 + medium_vuln * 5 + total_vuln * 1) / total_assets)
        else:
            risk_score = 0
        context['risk_score'] = round(risk_score, 1)
        
        # 漏洞等级分布
        vuln_distribution = {
            'critical': Vulnerability.objects.filter(severity='CRITICAL').count(),
            'high': Vulnerability.objects.filter(severity='HIGH').count(),
            'medium': Vulnerability.objects.filter(severity='MEDIUM').count(),
            'low': Vulnerability.objects.filter(severity='LOW').count(),
        }
        context['vuln_distribution'] = vuln_distribution
        
        return context

class TopologyView(TemplateView):
    template_name = 'scanner/topology.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # 限制资产数量，只显示最近活跃的100个
        assets = Asset.objects.all().select_related('category').order_by('-last_scanned')[:100]
        
        # 预先加载所有资产到字典，避免N+1查询
        assets_dict = {asset.ip_address: asset for asset in assets}
        
        nodes = []
        links = []
        
        # 1. 中心核心节点
        nodes.append({
            'name': 'Core Network',
            'symbolSize': 50,
            'itemStyle': {'color': '#0d6efd'},
            'category': 'Core'
        })
        
        segments = {}
        # 2. 网段节点
        for asset in assets:
            seg = asset.network_segment or 'Unknown Segment'
            if seg not in segments:
                segments[seg] = True
                nodes.append({
                    'name': seg,
                    'symbolSize': 35,
                    'itemStyle': {'color': '#6c757d'},
                    'category': 'Segment'
                })
                links.append({'source': 'Core Network', 'target': seg})
            
            # 3. 资产节点
            asset_name = f"{asset.ip_address}\n({asset.category.name if asset.category else '未知'})"
            nodes.append({
                'name': asset_name,
                'symbolSize': 20,
                'itemStyle': {'color': '#198754' if asset.is_up else '#dc3545'},
                'category': 'Asset',
                'value': asset.ip_address
            })
            links.append({'source': seg, 'target': asset_name})
            
        # 4. 增加流量连接关系 (从 PassiveEvent 提取)
        from django.db.models import Sum
        passive_links = PassiveEvent.objects.filter(
            src_ip__isnull=False, 
            dst_ip__isnull=False
        ).values('src_ip', 'dst_ip').annotate(
            total=Sum('count')
        ).order_by('-total')[:50]  # 限制为最重要的50条连接
        
        # 使用预先加载的字典查询，避免N+1问题
        for pl in passive_links:
            src_asset = assets_dict.get(pl['src_ip'])
            dst_asset = assets_dict.get(pl['dst_ip'])
            
            if src_asset and dst_asset:
                src_name = f"{src_asset.ip_address}\n({src_asset.category.name if src_asset.category else '未知'})"
                dst_name = f"{dst_asset.ip_address}\n({dst_asset.category.name if dst_asset.category else '未知'})"
                
                links.append({
                    'source': src_name,
                    'target': dst_name,
                    'lineStyle': {'width': min(pl['total'] / 10, 5), 'opacity': 0.6, 'curveness': 0.2},
                    'label': {'show': False}
                })
            
        context['topology_data'] = json.dumps({'nodes': nodes, 'links': links})
        return context

class AlertListView(ListView):
    model = Alert
    template_name = 'scanner/alert_list.html'
    context_object_name = 'alerts'
    paginate_by = 20

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # 告警状态筛选 (未读/已读)
        read_status = self.request.GET.get('read_status')
        if read_status == 'unread':
            queryset = queryset.filter(status='UNREAD')
        elif read_status == 'read':
            queryset = queryset.filter(status='READ')
        
        # 风险等级筛选
        severity = self.request.GET.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
            
        return queryset

@require_POST
def alert_mark_read(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    alert.status = 'READ'
    alert.save()
    return redirect(request.META.get('HTTP_REFERER', 'alert_list'))

@require_POST
def alert_mark_all_read(request):
    Alert.objects.filter(status='UNREAD').update(status='READ')
    messages.success(request, "所有告警已标记为已读")
    return redirect('alert_list')

@require_POST
def alert_resolve(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    alert.status = 'RESOLVED'
    alert.save()
    return redirect(request.META.get('HTTP_REFERER', 'alert_list'))

class TaskCreateView(CreateView):
    model = Task
    fields = ['target', 'scan_type', 'ports', 'enable_tcp', 'enable_udp', 'tcp_scan', 'host_discovery', 'timing', 'use_scripts', 'script_categories']
    template_name = 'scanner/task_form.html'
    success_url = reverse_lazy('task_list')

    def form_valid(self, form):
        self.object = form.save()
        # 在后台线程启动扫描，不阻塞页面跳转
        try:
            thread = threading.Thread(target=run_scan, args=(self.object.id,))
            thread.start()
            messages.success(self.request, f"任务已创建，正在后台开始扫描: {self.object.target}")
        except Exception as e:
            messages.error(self.request, f"启动后台扫描失败: {e}")
        
        return redirect(self.success_url)

class TaskListView(ListView):
    model = Task
    template_name = 'scanner/task_list.html'
    context_object_name = 'tasks'
    paginate_by = 10

class TaskDetailView(DetailView):
    model = Task
    template_name = 'scanner/task_detail.html'
    context_object_name = 'task'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        task = self.object

        primary_asset = None
        try:
            ipaddress.ip_address(task.target.strip())
            primary_asset = Asset.objects.filter(ip_address=task.target.strip()).first()
        except Exception:
            primary_asset = None

        task_assets = Asset.objects.none()
        if task.finished_at:
            task_assets = Asset.objects.filter(
                last_scanned__gte=task.created_at,
                last_scanned__lte=task.finished_at,
            ).order_by('ip_address')

        if not primary_asset and task_assets.count() == 1:
            primary_asset = task_assets.first()

        context['primary_asset'] = primary_asset
        context['task_assets'] = task_assets[:50]
        return context

class ScheduledTaskListView(ListView):
    model = ScheduledTask
    template_name = 'scanner/scheduled_task_list.html'
    context_object_name = 'scheduled_tasks'
    paginate_by = 10

class ScheduledTaskCreateView(CreateView):
    model = ScheduledTask
    fields = ['name', 'target', 'scan_type', 'ports', 'enable_tcp', 'enable_udp', 'tcp_scan', 
              'host_discovery', 'timing', 'use_scripts', 'script_categories',
              'interval_type', 'interval_value', 'specific_time', 'day_of_week']
    template_name = 'scanner/scheduled_task_form.html'
    success_url = reverse_lazy('scheduled_task_list')

    def form_valid(self, form):
        scheduled_task = form.save(commit=False)
        scheduled_task.next_run = self._calculate_next_run(scheduled_task)
        scheduled_task.save()
        messages.success(self.request, f"定时任务已创建: {scheduled_task.name}")
        return redirect(self.success_url)
    
    def _calculate_next_run(self, task):
        from datetime import datetime, timedelta, time
        now = timezone.now()
        
        if task.interval_type == 'MINUTES':
            return now + timedelta(minutes=task.interval_value)
        elif task.interval_type == 'HOURS':
            return now + timedelta(hours=task.interval_value)
        elif task.interval_type == 'DAILY':
            if task.specific_time:
                next_run = now.date()
                if task.specific_time > now.time():
                    return datetime.combine(next_run, task.specific_time)
                return datetime.combine(next_run + timedelta(days=1), task.specific_time)
            return now + timedelta(days=task.interval_value)
        elif task.interval_type == 'WEEKLY':
            if task.specific_time:
                return datetime.combine(now.date() + timedelta(days=1), task.specific_time)
            return now + timedelta(weeks=1)
        return now + timedelta(days=1)

class ScheduledTaskDetailView(DetailView):
    model = ScheduledTask
    template_name = 'scanner/scheduled_task_detail.html'
    context_object_name = 'scheduled_task'

@require_POST
def scheduled_task_toggle(request, pk):
    task = get_object_or_404(ScheduledTask, pk=pk)
    if task.status == 'ACTIVE':
        task.status = 'PAUSED'
        messages.success(request, f"任务已暂停: {task.name}")
    else:
        task.status = 'ACTIVE'
        task.next_run = calculate_next_run(task)
        messages.success(request, f"任务已启用: {task.name}")
    task.save()
    return redirect('scheduled_task_list')

@require_POST
def scheduled_task_run_now(request, pk):
    task = get_object_or_404(ScheduledTask, pk=pk)
    
    scan_task = Task.objects.create(
        target=task.target,
        scan_type=task.scan_type,
        ports=task.ports,
        enable_tcp=task.enable_tcp,
        enable_udp=task.enable_udp,
        tcp_scan=task.tcp_scan,
        host_discovery=task.host_discovery,
        timing=task.timing,
        use_scripts=task.use_scripts,
        script_categories=task.script_categories,
    )
    
    task.last_run = timezone.now()
    task.total_runs += 1
    task.next_run = calculate_next_run(task)
    task.save()
    
    thread = threading.Thread(target=run_scan, args=(scan_task.id,))
    thread.start()
    
    messages.success(request, f"立即执行任务已创建: {task.target}")
    return redirect('task_list')

@require_POST
def scheduled_task_delete(request, pk):
    task = get_object_or_404(ScheduledTask, pk=pk)
    task.delete()
    messages.success(request, "定时任务已删除")
    return redirect('scheduled_task_list')

def calculate_next_run(task):
    from datetime import datetime, timedelta
    now = timezone.now()
    
    if task.interval_type == 'MINUTES':
        return now + timedelta(minutes=task.interval_value)
    elif task.interval_type == 'HOURS':
        return now + timedelta(hours=task.interval_value)
    elif task.interval_type == 'DAILY':
        if task.specific_time:
            next_run = datetime.combine(now.date(), task.specific_time)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        return now + timedelta(days=task.interval_value)
    elif task.interval_type == 'WEEKLY':
        return now + timedelta(weeks=1)
    return now + timedelta(days=1)

class PassiveEventListView(ListView):
    model = PassiveEvent
    template_name = 'scanner/passive_event_list.html'
    context_object_name = 'events'
    paginate_by = 50

    def get_queryset(self):
        qs = super().get_queryset()
        event_type = self.request.GET.get('type')
        if event_type:
            qs = qs.filter(event_type=event_type.upper())
        q = (self.request.GET.get('q') or '').strip()
        if q:
            qs = qs.filter(Q(src_ip=q) | Q(dst_ip=q) | Q(hostname__icontains=q) | Q(url__icontains=q))
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sniffer_running'] = get_sniffer_status()
        return context

@require_POST
def passive_sniffer_control(request):
    action = request.POST.get('action')
    if action == 'start':
        if start_passive_monitoring():
            messages.success(request, "被动探测服务已启动，正在实时监听流量...")
        else:
            messages.error(request, "被动探测服务启动失败，请检查网络权限。")
    elif action == 'stop':
        if stop_passive_monitoring():
            messages.info(request, "被动探测服务已停止。")
        else:
            messages.error(request, "服务停止异常。")
    
    return redirect('passive_event_list')

class AssetListView(ListView):
    model = Asset
    template_name = 'scanner/asset_list.html'
    context_object_name = 'assets'
    paginate_by = 20

    def get_queryset(self):
        queryset = super().get_queryset().select_related('category').prefetch_related('alerts')
        
        # 搜索 - 支持正则表达式和高级搜索
        q = self.request.GET.get('q')
        if q:
            # 检测是否为正则表达式搜索
            if q.startswith('regex:') or q.startswith('re:'):
                import re
                pattern = q[6:] if q.startswith('regex:') else q[3:]
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                    queryset = queryset.extra(
                        where=["ip_address REGEXP %s OR hostname REGEXP %s OR mac_address REGEXP %s OR vendor REGEXP %s OR os_info REGEXP %s"],
                        params=[pattern, pattern, pattern, pattern, pattern]
                    )
                except re.error:
                    pass
            else:
                # 精确匹配模式: field:value
                if ':' in q:
                    parts = q.split(':', 1)
                    field = parts[0].lower()
                    value = parts[1]
                    
                    field_map = {
                        'ip': 'ip_address',
                        'ipaddress': 'ip_address',
                        'host': 'hostname',
                        'hostname': 'hostname',
                        'mac': 'mac_address',
                        'vendor': 'vendor',
                        'os': 'os_info',
                        'osinfo': 'os_info',
                        'cat': 'category__name',
                        'category': 'category__name',
                        'importance': 'importance',
                        'dept': 'department',
                        'department': 'department',
                        'biz': 'business_system',
                        'business': 'business_system',
                        'net': 'network_segment',
                        'network': 'network_segment',
                    }
                    
                    if field in field_map:
                        queryset = queryset.filter(**{f"{field_map[field]}__icontains": value})
                    else:
                        # 默认模糊搜索
                        queryset = queryset.filter(
                            Q(ip_address__icontains=q) | 
                            Q(hostname__icontains=q) | 
                            Q(mac_address__icontains=q) |
                            Q(vendor__icontains=q) |
                            Q(os_info__icontains=q)
                        )
                else:
                    # 普通模糊搜索
                    queryset = queryset.filter(
                        Q(ip_address__icontains=q) | 
                        Q(hostname__icontains=q) | 
                        Q(mac_address__icontains=q) |
                        Q(vendor__icontains=q) |
                        Q(os_info__icontains=q)
                    )
        
        # 过滤
        cat = self.request.GET.get('category')
        if cat:
            queryset = queryset.filter(category_id=cat)
            
        imp = self.request.GET.get('importance')
        if imp:
            queryset = queryset.filter(importance=imp)
            
        sys = self.request.GET.get('business_system')
        if sys:
            queryset = queryset.filter(business_system__icontains=sys)
            
        net = self.request.GET.get('network_segment')
        if net:
            queryset = queryset.filter(network_segment__icontains=net)
            
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from .models import Category
        context['categories'] = Category.objects.all()
        return context

class AssetDetailView(DetailView):
    model = Asset
    template_name = 'scanner/asset_detail.html'
    context_object_name = 'asset'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['ports'] = self.object.ports.all()
        context['vulns'] = self.object.vulns.all()
        context['passive_events'] = self.object.passive_events.all()[:50]
        context['change_logs'] = self.object.change_logs.all()[:20]
        return context

class AssetCreateView(CreateView):
    model = Asset
    fields = ['ip_address', 'hostname', 'os_info', 'mac_address', 'vendor', 'category', 'importance', 'business_system', 'department', 'network_segment']
    template_name = 'scanner/asset_form.html'
    success_url = reverse_lazy('asset_list')

    def form_valid(self, form):
        form.instance.discovery_method = 'MANUAL'
        response = super().form_valid(form)
        AssetChangeLog.objects.create(
            asset=self.object,
            change_type='手动新增',
            description=f"手动创建资产: {self.object.ip_address}"
        )
        messages.success(self.request, "资产创建成功")
        return response

class AssetUpdateView(UpdateView):
    model = Asset
    fields = ['hostname', 'os_info', 'mac_address', 'vendor', 'category', 'importance', 'business_system', 'department', 'network_segment']
    template_name = 'scanner/asset_form.html'
    
    def get_success_url(self):
        return reverse('asset_detail', kwargs={'pk': self.object.pk})

    def form_valid(self, form):
        old_obj = Asset.objects.get(pk=self.object.pk)
        response = super().form_valid(form)
        
        changes = []
        for field in form.changed_data:
            old_val = getattr(old_obj, field)
            new_val = getattr(self.object, field)
            changes.append(f"{field}: {old_val} -> {new_val}")
            
        if changes:
            AssetChangeLog.objects.create(
                asset=self.object,
                change_type='手动更新',
                description=" | ".join(changes)
            )
            messages.success(self.request, "资产信息更新成功")
        return response

def task_rescan(request, pk):
    """
    重新执行扫描任务
    """
    task = get_object_or_404(Task, pk=pk)
    task.status = 'PENDING'
    task.result_summary = ""
    task.finished_at = None
    task.save()
    
    # 启动后台线程重新扫描
    try:
        thread = threading.Thread(target=run_scan, args=(task.id,))
        thread.start()
        messages.success(request, f"已重新启动任务: {task.target}")
    except Exception as e:
        messages.error(request, f"重启任务失败: {e}")
        
    return redirect('task_list')

@require_POST
def batch_scan_create(request):
    from .models import Task
    from .tasks import run_scan
    
    target_text = request.POST.get('target_text', '').strip()
    scan_type = request.POST.get('scan_type', 'quick')
    scan_preset = request.POST.get('scan_preset', 'quick')
    
    if not target_text:
        messages.error(request, '请输入扫描目标')
        return redirect('batch_scan')
    
    lines = target_text.strip().split('\n')
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if parts:
            target = parts[0]
            if re.match(r'^[\d\.\-/]+$', target) or re.match(r'^[a-zA-Z0-9\.\-]+$', target):
                targets.append(target)
    
    if not targets:
        messages.error(request, '未找到有效的扫描目标')
        return redirect('batch_scan')
    
    task_names = []
    for target in targets:
        task = Task.objects.create(
            target=target,
            scan_type=scan_preset,
            status='PENDING'
        )
        run_scan.delay(task.id)
        task_names.append(target)
    
    messages.success(request, f'已创建 {len(task_names)} 个扫描任务并开始执行')
    return redirect('task_list')

def batch_scan_view(request):
    return render(request, 'scanner/batch_scan.html')

@require_POST
def task_delete(request, pk):
    task = get_object_or_404(Task, pk=pk)
    task.delete()
    messages.success(request, '任务已删除')
    return redirect('task_list')

@require_POST
def task_status_api(request):
    running_tasks = Task.objects.filter(status='RUNNING').values('id', 'status', 'progress', 'started_at')
    return JsonResponse({
        'running': list(running_tasks),
        'timestamp': timezone.now().isoformat()
    })

@require_POST
def asset_delete(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    asset.delete()
    messages.success(request, "资产已删除")
    return redirect('asset_list')

@require_POST
def asset_batch_delete(request):
    try:
        ids = json.loads(request.body).get('ids', [])
        if not ids:
            return JsonResponse({'success': False, 'error': 'No IDs provided'})
        
        deleted_count = Asset.objects.filter(id__in=ids).delete()[0]
        return JsonResponse({'success': True, 'deleted_count': deleted_count})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

class ReportListView(ListView):
    model = Report
    template_name = 'scanner/report_list.html'
    context_object_name = 'reports'
    paginate_by = 10

@require_POST
def generate_report(request):
    report_type = request.POST.get('report_type', 'TASK')
    target_id = request.POST.get('target_id')
    report_format = request.POST.get('format', 'HTML')
    name = request.POST.get('name', '')
    
    if not target_id and report_type == 'TASK':
        messages.error(request, '请选择一个任务')
        return redirect('report_generate')
    
    # 确保目标ID是整数
    try:
        target_id = int(target_id) if target_id else None
    except (ValueError, TypeError):
        target_id = None
    
    if report_type == 'TASK':
        task = get_object_or_404(Task, pk=target_id)
        assets = Asset.objects.filter(
            last_scanned__gte=task.created_at,
            last_scanned__lte=task.finished_at
        ) if task.finished_at else Asset.objects.none()
        target = task.target
        report_name = name or f"扫描报告 - {task.target}"
    else:
        assets = Asset.objects.all()
        target = '全部资产'
        report_name = name or f"资产报告 - {timezone.now().strftime('%Y-%m-%d')}"
    
    vulns = Vulnerability.objects.filter(asset__in=assets)
    high_count = vulns.filter(severity='HIGH').count()
    medium_count = vulns.filter(severity='MEDIUM').count()
    low_count = vulns.filter(severity='LOW').count()
    
    asset_data = []
    for asset in assets[:100]:
        asset_vulns = asset.vulns.all()
        asset_data.append({
            'ip': asset.ip_address,
            'hostname': asset.hostname,
            'os': asset.os_info,
            'vendor': asset.vendor,
            'ports': list(asset.ports.values_list('port_number', 'service_name')),
            'vulns': list(asset_vulns.values('name', 'severity', 'cve_id')),
        })
    
    content = {
        'target': target,
        'scan_time': timezone.now().isoformat(),
        'assets': asset_data,
        'statistics': {
            'total_assets': assets.count(),
            'total_vulns': vulns.count(),
            'high_vulns': high_count,
            'medium_vulns': medium_count,
            'low_vulns': low_count,
            'os_distribution': list(assets.values('os_info').annotate(count=Count('id')).order_by('-count')[:10]),
            'vendor_distribution': list(assets.values('vendor').annotate(count=Count('id')).order_by('-count')[:10]),
        }
    }
    
    report = Report.objects.create(
        name=report_name,
        report_type=report_type,
        format=report_format,
        target=target,
        asset_count=assets.count(),
        vuln_count=vulns.count(),
        high_vuln_count=high_count,
        medium_vuln_count=medium_count,
        low_vuln_count=low_count,
        summary=f"扫描目标: {target}, 资产数量: {assets.count()}, 漏洞数量: {vulns.count()} (高危: {high_count}, 中危: {medium_count}, 低危: {low_count})",
        content=content,
    )
    
    messages.success(request, f"报告已生成: {report.name}")
    return redirect('report_detail', pk=report.id)

def report_detail(request, pk):
    report = get_object_or_404(Report, pk=pk)
    return render(request, 'scanner/report_detail.html', {'report': report})

def report_download(request, pk):
    report = get_object_or_404(Report, pk=pk)
    
    if report.format == 'JSON':
        content = json.dumps(report.content, indent=2, ensure_ascii=False)
        content_type = 'application/json'
        extension = 'json'
    elif report.format == 'CSV':
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP', '主机名', '操作系统', '厂商', '端口/服务', '漏洞'])
        for asset in report.content.get('assets', []):
            ports = ', '.join([f"{p[0]}/{p[1]}" for p in asset.get('ports', [])])
            vulns = ', '.join([v['name'] for v in asset.get('vulns', [])])
            writer.writerow([asset['ip'], asset['hostname'], asset['os'], asset['vendor'], ports, vulns])
        content = output.getvalue()
        content_type = 'text/csv'
        extension = 'csv'
    else:
        content = render_to_string('scanner/report_template.html', {'report': report})
        content_type = 'text/html'
        extension = 'html'
    
    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="report_{report.id}.{extension}"'
    return response

def export_assets_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="assets_ledger.csv"'
    
    # 解决中文乱码
    response.write('\ufeff'.encode('utf8'))
    
    writer = csv.writer(response)
    writer.writerow([
        'IP 地址', '主机名', 'MAC 地址', '厂商', 
        '操作系统', '资产类型', '重要程度', 
        '所属业务系统', '归属部门', '所属网段',
        '开放端口数', '最后扫描时间'
    ])
    
    assets = Asset.objects.all().select_related('category')
    for asset in assets:
        writer.writerow([
            asset.ip_address,
            asset.hostname or '-',
            asset.mac_address or '-',
            asset.vendor or '-',
            asset.os_info or '-',
            asset.category.name if asset.category else '-',
            asset.get_importance_display(),
            asset.business_system or '-',
            asset.department or '-',
            asset.network_segment or '-',
            asset.open_ports_count,
            asset.last_scanned.strftime('%Y-%m-%d %H:%M:%S') if asset.last_scanned else '-'
        ])
        
    return response

def passive_import(request):
    if request.method == 'GET':
        return render(request, 'scanner/passive_import.html')

    upload = request.FILES.get('file')
    source = (request.POST.get('source') or '').strip() or 'upload'
    if not upload:
        return HttpResponseBadRequest('missing file')

    content = upload.read()
    try:
        text = content.decode('utf-8-sig', errors='ignore')
    except Exception:
        text = content.decode(errors='ignore')

    imported = 0
    failed = 0

    if upload.name.lower().endswith('.csv'):
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            try:
                ingest_event(row, source=source)
                imported += 1
            except Exception:
                failed += 1
        messages.success(request, f'导入完成：成功 {imported} 条，失败 {failed} 条')
        return redirect('passive_event_list')

    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) == 1:
        try:
            obj = json.loads(lines[0])
        except Exception:
            return HttpResponseBadRequest('invalid json')
        if isinstance(obj, list):
            for item in obj:
                try:
                    ingest_event(item, source=source)
                    imported += 1
                except Exception:
                    failed += 1
        elif isinstance(obj, dict):
            try:
                ingest_event(obj, source=source)
                imported = 1
            except Exception:
                failed = 1
        else:
            return HttpResponseBadRequest('invalid json')
    else:
        for line in lines:
            try:
                obj = json.loads(line)
                ingest_event(obj, source=source)
                imported += 1
            except Exception:
                failed += 1

    messages.success(request, f'导入完成：成功 {imported} 条，失败 {failed} 条')
    return redirect('passive_event_list')

@csrf_exempt
def passive_ingest_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'method_not_allowed'}, status=405)
    if not validate_ingest_token(request):
        return JsonResponse({'error': 'unauthorized'}, status=401)
    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        return JsonResponse({'error': 'invalid_json'}, status=400)

    imported = 0
    failed = 0

    if isinstance(payload, list):
        for item in payload:
            try:
                ingest_event(item, source='api')
                imported += 1
            except Exception:
                failed += 1
    elif isinstance(payload, dict):
        try:
            ingest_event(payload, source='api')
            imported = 1
        except Exception:
            failed = 1
    else:
        return JsonResponse({'error': 'invalid_payload'}, status=400)

    return JsonResponse({'imported': imported, 'failed': failed})
