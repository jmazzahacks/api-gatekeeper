"""Route Gunicorn lifecycle logs through the application's Loki pipeline."""
import logging
import os

from byteforge_loki_logging import configure_logging
from dotenv import load_dotenv
from gunicorn.config import Config
from gunicorn.glogging import Logger


class GatekeeperLogger(Logger):
    """Initialize before arbiter startup, and restore routing on reload.

    Requires byteforge-loki-logging 0.1.11's fork-safe queues. Workers may
    reconfigure logging in create_app(); early boot records are drained there.
    """

    def setup(self, cfg: Config) -> None:
        super().setup(cfg)
        load_dotenv()
        configure_logging(
            application_tag='api-gatekeeper',
            debug_local=os.environ.get('DEBUG_LOCAL', 'true').lower() == 'true',
            local_level=os.environ.get('LOG_LEVEL', 'INFO'),
        )
        for name in ('gunicorn', 'gunicorn.error', 'gunicorn.access'):
            logger = logging.getLogger(name)
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
                if getattr(handler, "_gunicorn", False):
                    handler.close()
            logger.propagate = True
            logger.setLevel(logging.NOTSET)
