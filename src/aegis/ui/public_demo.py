"""Disposable, per-browser Streamlit workspace for the public jury demo."""
from pathlib import Path
import shutil
import tempfile

from aegis.detection.engine import assess
from aegis.ingestion.importer import ingest

ROOT = Path(__file__).resolve().parents[3]
SESSION_KEY = 'aegis_public_workspace'


def session_workspace(state) -> Path:
    existing = state.get(SESSION_KEY)
    if existing:
        return Path(existing)
    workspace = Path(tempfile.mkdtemp(prefix='aegis-public-'))
    workspace.chmod(0o700)
    try:
        db = workspace / 'demo.sqlite'
        collection = ingest(ROOT / 'demo/positive.zip', db)
        assess(db, ROOT / 'rules/detection.json', collection['collection_id'])
    except Exception:
        shutil.rmtree(workspace)
        raise
    state[SESSION_KEY] = str(workspace)
    return workspace


def reset_session_workspace(state) -> None:
    previous = state.get(SESSION_KEY)
    if previous:
        workspace = Path(previous)
        if workspace.parent == Path(tempfile.gettempdir()) and workspace.name.startswith('aegis-public-'):
            shutil.rmtree(workspace, ignore_errors=True)
    for key in list(state):
        del state[key]
