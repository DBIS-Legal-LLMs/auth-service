"""A daily error log file next to the console output.

WARNING and ERROR records (including the tracebacks of unhandled exceptions) are appended to
`<LOG_DIR>/auth-service-errors-YYYY-MM-DD.log`, one file per UTC day. INFO and below are not written, the
console and uvicorn's access log are left as they are.

Bounds, so that the log can never fill the disk of the server:
  * files older than `LOG_RETENTION_DAYS` days are deleted (when a new day starts and at startup);
  * a day's file stops growing at `LOG_MAX_FILE_MB` (one last line says so; the console still gets everything).

A missing or unwritable directory never stops the service: one warning goes to the console and the file is
skipped.
"""

import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

LOG_FILE_PREFIX = "auth-service-errors-"
_FILE_NAME = re.compile(r"^auth-service-errors-(\d{4}-\d{2}-\d{2})\.log$")
_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


class DailyErrorFileHandler(logging.Handler):
    def __init__(self, directory: str, retention_days: int = 30, max_file_bytes: int = 20 * 1024 * 1024):
        super().__init__(level=logging.WARNING)
        self.directory = directory
        self.retention_days = max(1, retention_days)
        self.max_file_bytes = max_file_bytes
        self.setFormatter(_formatter())
        self.addFilter(lambda record: not record.name.startswith("uvicorn.access"))
        self._day: str | None = None
        self._stream = None
        self._size = 0
        self._full = False
        self._disabled = False
        os.makedirs(directory, exist_ok=True)
        self._open(self._today())  # fail here, not on the first error, if the directory cannot be used

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def path_for(self, day: str) -> str:
        return os.path.join(self.directory, f"{LOG_FILE_PREFIX}{day}.log")

    def _open(self, day: str) -> None:
        if self._stream is not None:
            self._stream.close()
        self._stream = open(self.path_for(day), "a", encoding="utf-8")
        self._day = day
        self._size = os.path.getsize(self.path_for(day))
        self._full = self._size >= self.max_file_bytes
        self._prune(day)

    def _prune(self, today: str) -> None:
        oldest_kept = datetime.strptime(today, "%Y-%m-%d") - timedelta(days=self.retention_days - 1)
        for name in os.listdir(self.directory):
            match = _FILE_NAME.match(name)
            if match and datetime.strptime(match.group(1), "%Y-%m-%d") < oldest_kept:
                try:
                    os.remove(os.path.join(self.directory, name))
                except OSError:
                    pass

    def emit(self, record: logging.LogRecord) -> None:
        if self._disabled:
            return
        try:
            day = datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%d")
            if day != self._day:
                self._open(day)
            if self._full:
                return
            line = self.format(record) + "\n"
            if self._size + len(line.encode("utf-8")) > self.max_file_bytes:
                self._full = True
                line = f"{datetime.now(timezone.utc).isoformat()} the day's size limit of {self.max_file_bytes} bytes is reached, nothing more is written to this file today\n"
            self._stream.write(line)
            self._stream.flush()
            self._size += len(line.encode("utf-8"))
        except OSError as error:
            self._disabled = True
            print(f"WARNING: the error log file {self.directory} can no longer be written ({error}); continuing without it", file=sys.stderr)

    def close(self) -> None:
        with self.lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
        super().close()


def _formatter() -> logging.Formatter:
    formatter = logging.Formatter(_FORMAT)
    formatter.converter = time.gmtime
    return formatter


def _loggers() -> list[logging.Logger]:
    # uvicorn's own logger does not propagate to the root logger and logs the traceback of an unhandled
    # exception ("Exception in ASGI application"); its access log is deliberately left out
    return [logging.getLogger(), logging.getLogger("uvicorn.error")]


def install_error_log(directory: str, retention_days: int, max_file_mb: int) -> DailyErrorFileHandler | None:
    """Attach the daily file to the root and uvicorn error loggers. Returns the handler, or None if the
    directory cannot be used (a warning goes to the console)."""
    remove_error_log()
    try:
        handler = DailyErrorFileHandler(directory, retention_days, max_file_mb * 1024 * 1024)
    except OSError as error:
        print(f"WARNING: no error log file in {directory!r} ({error}); continuing without it", file=sys.stderr)
        return None

    root = logging.getLogger()
    if not root.handlers:
        # as before: without a handler Python prints WARNING and above to stderr; keep that now that the
        # root logger has a handler of its own
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.WARNING)
        console.setFormatter(_formatter())
        root.addHandler(console)
    for logger in _loggers():
        logger.addHandler(handler)
    return handler


def remove_error_log() -> None:
    for logger in _loggers():
        for handler in list(logger.handlers):
            if isinstance(handler, DailyErrorFileHandler):
                logger.removeHandler(handler)
                handler.close()
