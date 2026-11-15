"""Public demo entrypoint; the on-premise dashboard remains separate."""
import os

os.environ['AEGIS_PUBLIC_DEMO'] = '1'

from aegis.ui import dashboard  # noqa: E402,F401
