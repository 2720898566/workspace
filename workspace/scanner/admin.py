from django.contrib import admin
from .models import Task, Asset, Port, Vulnerability, Category, Tag, AssetChangeLog, PassiveEvent

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')

@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('name',)

class PortInline(admin.TabularInline):
    model = Port
    extra = 0

class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'hostname', 'os_info', 'category', 'importance', 'is_up', 'last_scanned')
    list_filter = ('category', 'importance', 'is_up', 'os_info')
    search_fields = ('ip_address', 'hostname', 'mac_address')
    inlines = [PortInline, VulnerabilityInline]
    filter_horizontal = ('tags',)

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('target', 'scan_type', 'status', 'created_at', 'finished_at')
    list_filter = ('scan_type', 'status')
    readonly_fields = ('created_at', 'finished_at')

@admin.register(AssetChangeLog)
class AssetChangeLogAdmin(admin.ModelAdmin):
    list_display = ('asset', 'change_type', 'timestamp', 'description')
    list_filter = ('change_type', 'timestamp')
    search_fields = ('asset__ip_address', 'description')

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('asset', 'port_number', 'protocol', 'service_name', 'state')
    list_filter = ('protocol', 'state', 'service_name')

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('name', 'asset', 'severity', 'cve_id')
    list_filter = ('severity',)
    search_fields = ('name', 'asset__ip_address', 'cve_id')

@admin.register(PassiveEvent)
class PassiveEventAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'source', 'asset', 'src_ip', 'dst_ip', 'dst_port', 'hostname', 'last_seen', 'count')
    list_filter = ('event_type', 'source')
    search_fields = ('hostname', 'url', 'src_ip', 'dst_ip')
