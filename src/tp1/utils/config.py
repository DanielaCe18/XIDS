import logging
import sys

logger = logging.getLogger("TP1")
logger.setLevel(logging.DEBUG)

# Formatteur clair
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)
