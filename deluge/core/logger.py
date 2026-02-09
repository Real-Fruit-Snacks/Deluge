import logging
from rich.logging import RichHandler


def setup_logger(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )
    return logging.getLogger("deluge")


def mute_logger():
    """Mutes the deluge logger."""
    logger = logging.getLogger("deluge")
    logger.disabled = True


def unmute_logger():
    """Unmutes the deluge logger."""
    logger = logging.getLogger("deluge")
    logger.disabled = False
