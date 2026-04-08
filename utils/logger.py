"""
utils/logger.py
Centralized logger — writes to stderr so MCP stdio transport (stdout) is not polluted.
"""
import sys
import logging
from rich.logging import RichHandler

# Suppress noisy MCP internal logs
logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("mcp.server").setLevel(logging.WARNING)
logging.getLogger("mcp.client").setLevel(logging.WARNING)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False, console=__import__("rich.console", fromlist=["Console"]).Console(stderr=True))],
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
