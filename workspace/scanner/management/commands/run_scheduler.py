from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from scanner.models import ScheduledTask, Task
from scanner.tasks import run_scan
import threading


class Command(BaseCommand):
    help = 'Run the scheduled task scheduler'

    def add_arguments(self, parser):
        parser.add_argument(
            '--once',
            action='store_true',
            help='Run scheduler once instead of continuously',
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=60,
            help='Check interval in seconds (default: 60)',
        )

    def handle(self, *args, **options):
        interval = options['interval']
        run_once = options['once']

        self.stdout.write(self.style.SUCCESS('Scheduler started...'))

        while True:
            self.check_and_run_tasks()

            if run_once:
                break

            import time
            time.sleep(interval)

    def check_and_run_tasks(self):
        now = timezone.now()

        tasks = ScheduledTask.objects.filter(
            status='ACTIVE',
            next_run__lte=now
        )

        for scheduled_task in tasks:
            self.run_scheduled_task(scheduled_task)

    def run_scheduled_task(self, scheduled_task):
        self.stdout.write(f'Running scheduled task: {scheduled_task.name}')

        task = Task.objects.create(
            target=scheduled_task.target,
            scan_type=scheduled_task.scan_type,
            ports=scheduled_task.ports,
            enable_tcp=scheduled_task.enable_tcp,
            enable_udp=scheduled_task.enable_udp,
            tcp_scan=scheduled_task.tcp_scan,
            host_discovery=scheduled_task.host_discovery,
            timing=scheduled_task.timing,
            use_scripts=scheduled_task.use_scripts,
            script_categories=scheduled_task.script_categories,
            status='PENDING'
        )

        scheduled_task.last_run = timezone.now()
        scheduled_task.total_runs += 1
        scheduled_task.next_run = self.calculate_next_run(scheduled_task)
        scheduled_task.save()

        thread = threading.Thread(target=run_scan, args=(task.id,))
        thread.start()

        self.stdout.write(f'Created scan task {task.id} for scheduled task {scheduled_task.name}')

    def calculate_next_run(self, task):
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
