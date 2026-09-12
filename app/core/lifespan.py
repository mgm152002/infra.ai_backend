"""Application startup lifecycle."""

import os
import threading

from fastapi import FastAPI

from app.core.config import settings
from app.core.logger import logger
from app.services.chat_service import CHAT_QUEUE_NAME, chat_worker_loop
from app.services.escalation_service import EscalationService
from worker import worker_loop


async def worker_lifespan(app: FastAPI):
    """Start incident, chat, and escalation workers with the application."""
    try:
        EscalationService.start_monitoring()
    except Exception as exc:
        logger.error(f"Failed to start Escalation Monitor: {exc}")

    try:
        worker_count = int(os.getenv("WORKER_COUNT", "1"))
    except (TypeError, ValueError):
        worker_count = 1
    worker_count = min(max(worker_count, 1), 64)

    threads = []
    for index in range(worker_count):
        thread = threading.Thread(
            target=worker_loop,
            daemon=True,
            name=f"Worker-{index + 1}",
        )
        thread.start()
        threads.append(thread)

    try:
        chat_worker_count = int(os.getenv("CHAT_WORKER_COUNT", "1"))
    except (TypeError, ValueError):
        chat_worker_count = 1
    chat_worker_count = min(max(chat_worker_count, 1), 64)

    incident_queue_name = os.getenv("SQS_QUEUE_NAME", settings.SQS_QUEUE_NAME or "Chatqueue")
    if CHAT_QUEUE_NAME == incident_queue_name:
        logger.warning(
            f"CHAT_QUEUE_NAME ('{CHAT_QUEUE_NAME}') matches incident SQS queue "
            f"('{incident_queue_name}'). Disabling chat workers to avoid queue contention."
        )
        chat_worker_count = 0

    for index in range(chat_worker_count):
        thread = threading.Thread(
            target=chat_worker_loop,
            daemon=True,
            name=f"ChatWorker-{index + 1}",
        )
        thread.start()
        threads.append(thread)

    app.state.worker_threads = threads
    yield
