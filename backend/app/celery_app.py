# backend/app/celery_app.py
from celery import Celery
from celery.schedules import crontab
import os

# Redis connection (use environment variables in production)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

celery_app = Celery(
    "vulnora",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.routers.scans"]   # where your tasks will live
)

# Optional: Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,        # 30 minutes max per scan
    task_soft_time_limit=1500,
    worker_prefetch_multiplier=1,  # important for long-running tasks
)

# Optional: Scheduled tasks (e.g., daily template updates)
celery_app.conf.beat_schedule = {
    "update-nuclei-templates": {
        "task": "app.routers.scans.update_nuclei_templates",
        "schedule": crontab(hour=3, minute=0),   # every day at 3 AM
    },
}
