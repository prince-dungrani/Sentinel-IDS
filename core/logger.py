import json
from logging import FileHandler
import logging

logger = logging.getLogger("IDS")

handler = FileHandler("logs/alerts.json", mode="a")

logger.setLevel(logging.INFO)
logger.addHandler(handler)

class IDSLogger:

    def log(self, alert):

        logger.info(json.dumps(alert))