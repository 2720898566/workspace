from django.urls import path
from . import views

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('passive/', views.PassiveEventListView.as_view(), name='passive_event_list'),
    path('passive/import/', views.passive_import, name='passive_import'),
    path('api/passive/events/', views.passive_ingest_api, name='passive_ingest_api'),
    path('passive/control/', views.passive_sniffer_control, name='passive_sniffer_control'),
    path('tasks/', views.TaskListView.as_view(), name='task_list'),
    path('tasks/create/', views.TaskCreateView.as_view(), name='task_create'),
    path('tasks/<int:pk>/', views.TaskDetailView.as_view(), name='task_detail'),
    path('tasks/<int:pk>/rescan/', views.task_rescan, name='task_rescan'),
    path('tasks/<int:pk>/delete/', views.task_delete, name='task_delete'),
    path('tasks/batch/', views.batch_scan_view, name='batch_scan'),
    path('tasks/batch-scan/', views.batch_scan_create, name='batch_scan_create'),
    path('api/tasks/status/', views.task_status_api, name='task_status_api'),
    
    # 定时任务
    path('scheduled/', views.ScheduledTaskListView.as_view(), name='scheduled_task_list'),
    path('scheduled/create/', views.ScheduledTaskCreateView.as_view(), name='scheduled_task_create'),
    path('scheduled/<int:pk>/', views.ScheduledTaskDetailView.as_view(), name='scheduled_task_detail'),
    path('scheduled/<int:pk>/toggle/', views.scheduled_task_toggle, name='scheduled_task_toggle'),
    path('scheduled/<int:pk>/run-now/', views.scheduled_task_run_now, name='scheduled_task_run_now'),
    path('scheduled/<int:pk>/delete/', views.scheduled_task_delete, name='scheduled_task_delete'),
    
    path('assets/', views.AssetListView.as_view(), name='asset_list'),
    path('assets/create/', views.AssetCreateView.as_view(), name='asset_create'),
    path('assets/<int:pk>/', views.AssetDetailView.as_view(), name='asset_detail'),
    path('assets/<int:pk>/update/', views.AssetUpdateView.as_view(), name='asset_update'),
    path('assets/<int:pk>/delete/', views.asset_delete, name='asset_delete'),
    path('assets/export/', views.export_assets_csv, name='asset_export'),
    path('assets/batch-delete/', views.asset_batch_delete, name='asset_batch_delete'),
    path('reports/generate/', views.generate_report, name='report_generate'),
    path('reports/<int:pk>/', views.report_detail, name='report_detail'),
    path('reports/<int:pk>/download/', views.report_download, name='report_download'),
    path('topology/', views.TopologyView.as_view(), name='topology'),
    path('alerts/', views.AlertListView.as_view(), name='alert_list'),
    path('alerts/mark-all-read/', views.alert_mark_all_read, name='alert_mark_all_read'),
    path('alerts/<int:pk>/read/', views.alert_mark_read, name='alert_mark_read'),
    path('alerts/<int:pk>/resolve/', views.alert_resolve, name='alert_resolve'),
]
