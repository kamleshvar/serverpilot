"""Structured, redacting logging configuration."""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, has_request_context
from flask import request as flask_request

request_id_var: ContextVar[str] = ContextVar("serverpilot_request_id", default="-")

_SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(password|passwd|secret|client_secret|api[_-]?key|"
        r"authorization|private[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"webhook[_-]?secret|signing[_-]?secret)\b"
        r"(\s*[:=]\s*)(['\"]?)([^\s'\"&,;]{4,})"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
]


def redact(value: str) -> str:
    if not value:
        return value
    redacted = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 4:
            redacted = pattern.sub(
                lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED]",
                redacted,
            )
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            redacted = redact(message)
            if redacted != message:
                record.msg = redacted
                record.args = ()
        except Exception:  # noqa: BLE001 - logging must never break requests
            record.msg = "[log redaction failed]"
            record.args = ()
        return True


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        if has_request_context():
            record.method = flask_request.method
            record.path = flask_request.path
            record.remote_addr = flask_request.remote_addr or "-"
        else:
            record.method = "-"
            record.path = "-"
            record.remote_addr = "-"
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
            "method": getattr(record, "method", "-"),
            "path": getattr(record, "path", "-"),
            "remote_addr": getattr(record, "remote_addr", "-"),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


class TextFormatter(logging.Formatter):
    default_format = (
        "%(asctime)s %(levelname)-8s req=%(request_id)s %(name)s: %(message)s"
    )

    def __init__(self):
        super().__init__(self.default_format, datefmt="%Y-%m-%d %H:%M:%S")


def configure_logging(app: Flask) -> None:
    if getattr(app, "_serverpilot_logging_configured", False):
        return

    log_dir = Path(app.config["LOG_DIR"])
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir = Path(app.instance_path) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO)
    formatter = JsonFormatter() if app.config.get("LOG_JSON") else TextFormatter()
    filters = [RequestContextFilter(), RedactionFilter()]

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        if getattr(handler, "_serverpilot", False):
            root.removeHandler(handler)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    stream._serverpilot = True  # type: ignore[attr-defined]
    for flt in filters:
        stream.addFilter(flt)

    file_handler = RotatingFileHandler(
        log_dir / "serverpilot.log",
        maxBytes=int(app.config.get("LOG_MAX_BYTES", 10 * 1024 * 1024)),
        backupCount=int(app.config.get("LOG_BACKUP_COUNT", 10)),
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler._serverpilot = True  # type: ignore[attr-defined]
    for flt in filters:
        file_handler.addFilter(flt)

    if not app.config.get("TESTING"):
        root.addHandler(stream)
        root.addHandler(file_handler)
    else:
        root.addHandler(stream)

    for noisy in ("werkzeug", "urllib3", "botocore", "dns.resolver"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    app.logger.setLevel(level)
    app._serverpilot_logging_configured = True  # type: ignore[attr-defined]


def set_request_log_context(request_id: str) -> None:
    request_id_var.set(request_id)
    try:
        g.request_id = request_id
    except RuntimeError:  # outside request context
        pass
