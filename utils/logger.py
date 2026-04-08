"""
utils/logger.py
Centralized logger using rich for readable console output.
"""
import logging
from rich.logging import RichHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
