"""Public demo entrypoint; the on-premise dashboard remains separate."""
import os
from pathlib import Path
import runpy

os.environ['AEGIS_PUBLIC_DEMO'] = '1'

# Streamlit reruns this file on every interaction and for every visitor.
# Importing the UI caches its module and leaves subsequent runs blank.
runpy.run_path(str(Path(__file__).resolve().parent / 'src/aegis/ui/dashboard.py'),
               run_name='__main__')
