from .models import Alert
from django.conf import settings

def global_settings(request):
    return {
        'unread_alerts_count': Alert.objects.filter(status='UNREAD').count(),
        'simulation_mode': getattr(settings, 'SCANNER_SIMULATION_MODE', False)
    }
