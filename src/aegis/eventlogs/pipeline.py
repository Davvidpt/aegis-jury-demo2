"""Opt-in ZIP -> private EVTX staging -> Hayabusa -> additive SQLite storage."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from aegis.ingestion.importer import ingest, sha256_file
from aegis.ingestion.validator import CollectionError, validate_zip
from .contract import instant
from .storage import connect_eventlogs

MAX_ZIP = 100 * 1024**2
MAX_EVTX = 16 * 1024**2
MAX_TOTAL_EVTX = 64 * 1024**2
MAX_EVTX_FILES = 8
SUCCESS = {'MATCHES', 'NO_RULE_MATCHES'}
PARAMETERS = dict(contract='aegis-eventlogs-1', decoder='python-evtx==0.8.1', profile='super-verbose', minimum_level='medium',
                  threads=1, max_evtx_bytes=MAX_EVTX, max_evtx_total_bytes=MAX_TOTAL_EVTX,
                  max_files=MAX_EVTX_FILES, worker_timeout_seconds=120, run_timeout_seconds=600,
                  max_events_per_file=100000, memory_limit_mib=1536, output_file_limit_mib=64)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def identity(*parts):
    return hashlib.sha256('\0'.join(map(str, parts)).encode()).hexdigest()


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def tree_hash(path):
    digest = hashlib.sha256()
    for file in sorted(path.rglob('*')):
        if file.is_file():
            digest.update(file.relative_to(path).as_posix().encode() + b'\0' +
                          sha256_file(file).encode() + b'\n')
    return digest.hexdigest()


def verify_engine(engine, root):
    dist = (root / engine['distribution']).resolve()
    binary = (dist / engine['binary']).resolve()
    if not dist.is_relative_to(root.resolve()) or not binary.is_relative_to(dist):
        raise ValueError('Engine paths must stay within the operator-supplied engine root')
    if sha256_file(binary) != engine['binary_sha256']:
        raise ValueError('Engine binary hash mismatch')
    for directory in ('rules', 'config'):
        if tree_hash(dist / directory) != engine[directory + '_tree_sha256']:
            raise ValueError(f'Engine {directory} hash mismatch')
    return dist


def copy_bounded(stream, target, maximum):
    total = 0
    with target.open('xb') as out:
        target.chmod(0o600)
        while block := stream.read(1024 * 1024):
            total += len(block)
            if total > maximum:
                raise CollectionError('Input exceeds configured size limit')
            out.write(block)


def run_worker(source, dist, engine, digest, work, timeout=120):
    command = [sys.executable, '-m', 'aegis.eventlogs.worker', '--source', str(source),
               '--dist', str(dist), '--binary', engine['binary'], '--digest', digest, '--work', str(work)]
    env = os.environ.copy()
    env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2])
    with (work / 'worker.stdout').open('w') as out, (work / 'worker.stderr').open('w') as err:
        process = subprocess.Popen(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            if isinstance(exc, subprocess.TimeoutExpired):
                return {'status': 'TIMEOUT'}
            raise
    result_path = work / 'result.json'
    if code or not result_path.is_file():
        return {'status': 'WORKER_ERROR', 'exit_code': code}
    if result_path.stat().st_size > 64 * 1024**2:
        return {'status': 'OUTPUT_LIMIT'}
    return json.loads(result_path.read_text())


def get_run(db, run_id, reused=False):
    row = dict(db.execute('SELECT * FROM analysis_runs WHERE id=?', (run_id,)).fetchone())
    files = [dict(r) for r in db.execute('''SELECT source_member,file_sha256,size_bytes,status,
                   diagnostics_json FROM eventlog_files WHERE run_id=? ORDER BY id''', (run_id,))]
    return {'analysis_id': run_id, 'collection_id': row['collection_id'], 'status': row['status'],
            'engine': row['engine'], 'engine_version': row['engine_version'], 'reused': reused,
            'findings_count': db.execute('SELECT count(*) FROM analysis_findings WHERE run_id=?', (run_id,)).fetchone()[0],
            'master_zip': row['master_zip'], 'output_dir': row['output_dir'],
            'diagnostics': json.loads(row['diagnostics_json']), 'files': files}


def persist_file(db, run_id, collection_id, zip_digest, member, digest, size, result):
    diagnostics = {k: v for k, v in result.items() if k not in ('events', 'findings', 'references')}
    file_id = db.execute('''INSERT INTO eventlog_files
        (run_id,source_member,file_sha256,size_bytes,status,diagnostics_json) VALUES (?,?,?,?,?,?)''',
        (run_id, member, digest, size, result['status'], canonical(diagnostics))).lastrowid
    if result['status'] not in SUCCESS:
        return
    by_offset = {}
    for event in result['events']:
        # Include ZIP/member scope: repeated RecordIDs or identical files in
        # distinct collections must not steal each other's provenance.
        eid = identity(zip_digest, member, digest, event['byte_offset'])
        by_offset[event['byte_offset']] = eid
        db.execute('''INSERT OR IGNORE INTO eventlog_events
            VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            (eid, collection_id, member, digest, event['byte_offset'], event['EventRecordID'],
             event['Channel'], event['Computer'], event['EventID'],
             instant(event['timestamp']).isoformat(), event['xml']))
    for finding, reference in zip(result['findings'], result['references'], strict=True):
        stable = finding | {'EvtxFile': member}
        key = identity(member, canonical(stable))
        db.execute('''INSERT OR IGNORE INTO analysis_findings
            (run_id,file_id,finding_key,rule_id,title,severity,reference_status,raw_json)
            VALUES (?,?,?,?,?,?,?,?)''',
            (run_id, file_id, key, finding['RuleID'], finding['RuleTitle'], finding['Level'],
             reference['status'], canonical(stable)))
        fid = db.execute('SELECT id FROM analysis_findings WHERE run_id=? AND finding_key=?',
                         (run_id, key)).fetchone()[0]
        for ref in reference['evidence_refs']:
            db.execute('INSERT OR IGNORE INTO analysis_finding_evidence VALUES (?,?)',
                       (fid, by_offset[ref['byte_offset']]))


def analyze_zip(path: Path, db_path: Path, store: Path, manifest: Path, engine_root: Path,
                retry: bool = False):
    db_path = db_path.expanduser().absolute()
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Serialize M6 writers per DB without keeping a SQLite write transaction
    # open while an external engine runs. A crashed process releases flock.
    fd = os.open(str(db_path) + '.evtx.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another EVTX analysis is using this database') from exc
        return _analyze(path, db_path, store, manifest, engine_root, retry)


def _analyze(path, db_path, store, manifest, engine_root, retry):
    engine = json.loads(manifest.read_text())['engine']
    if engine['version'] != '3.3.0':
        raise ValueError('Only the verified Hayabusa 3.3.0 output contract is supported')
    store = store.expanduser().resolve()
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    if store.stat().st_mode & 0o077:
        raise ValueError('EVTX store must be private (chmod 700)')
    work = Path(tempfile.mkdtemp(prefix='analysis-', dir=store))
    master = work / 'master.zip'
    with path.open('rb') as source:
        copy_bounded(source, master, MAX_ZIP)
    zip_digest = sha256_file(master)
    archive, results = validate_zip(master, allow_evtx_only=True)
    with archive:
        members = sorted((i for i in archive.infolist() if not i.is_dir() and
                          i.filename.startswith('uploads/') and i.filename.lower().endswith('.evtx')),
                         key=lambda i: i.filename)
        if len(members) > MAX_EVTX_FILES or sum(i.file_size for i in members) > MAX_TOTAL_EVTX:
            raise CollectionError('EVTX collection exceeds 8 files or 64 MiB total')
        if any(i.file_size > MAX_EVTX for i in members):
            raise CollectionError('EVTX member exceeds 16 MiB; do not silently truncate evidence')
        # JSON ingestion remains the existing atomic M1 flow. EVTX-only ZIPs
        # get an explicit investigation collection, without invented JSON rows.
        if results:
            collection_id = ingest(master, db_path)['collection_id']
        else:
            collection_id = None
        db = connect_eventlogs(db_path)
        try:
            with db:
                if collection_id is None:
                    db.execute('''INSERT OR IGNORE INTO collections
                        (zip_sha256,filename,imported_at_utc,profile,status) VALUES (?,?,?,?,?)''',
                        (zip_digest, path.name, utcnow(), 'investigation-1', 'imported'))
                    collection_id = db.execute('SELECT id FROM collections WHERE zip_sha256=?', (zip_digest,)).fetchone()[0]
                # The staged filename is generic; preserve original receipt name.
                db.execute('UPDATE collections SET filename=? WHERE id=? AND filename=?',
                           (path.name, collection_id, 'master.zip'))
            run_key = identity(zip_digest, canonical(engine), canonical(PARAMETERS))
            old = db.execute('SELECT id,status FROM analysis_runs WHERE run_key=?', (run_key,)).fetchone()
            if old:
                if old['status'] == 'RUNNING':
                    with db:
                        db.execute("UPDATE analysis_runs SET status='INTERRUPTED' WHERE id=?", (old['id'],))
                if not retry or old['status'] in SUCCESS or old['status'] == 'UNRESOLVED':
                    saved = db.execute('SELECT master_zip FROM analysis_runs WHERE id=?', (old['id'],)).fetchone()[0]
                    if sha256_file(Path(saved)) != zip_digest:
                        raise ValueError('Stored ZIP master hash mismatch; restore the verified master before reuse')
                    # Remove only this unused private receipt copy, not the saved run.
                    master.unlink()
                    work.rmdir()
                    return get_run(db, old['id'], reused=True)
            with db:
                if old:
                    run_id = old['id']
                    db.execute('DELETE FROM analysis_finding_evidence WHERE finding_id IN (SELECT id FROM analysis_findings WHERE run_id=?)', (run_id,))
                    db.execute('DELETE FROM analysis_findings WHERE run_id=?', (run_id,))
                    db.execute('DELETE FROM eventlog_files WHERE run_id=?', (run_id,))
                    db.execute('''UPDATE analysis_runs SET status='RUNNING',created_at_utc=?,finished_at_utc=NULL,
                        master_zip=?,output_dir=?,diagnostics_json='{}' WHERE id=?''',
                        (utcnow(), str(master), str(work), run_id))
                else:
                    run_id = db.execute('''INSERT INTO analysis_runs
                        (collection_id,run_key,engine,engine_version,manifest_json,parameters_json,
                         created_at_utc,status,master_zip,output_dir) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                        (collection_id, run_key, 'hayabusa', engine['version'], canonical(engine),
                         canonical(PARAMETERS), utcnow(), 'RUNNING', str(master), str(work))).lastrowid
            (work / 'run.json').write_text(canonical(dict(run_id=run_id, engine=engine, parameters=PARAMETERS,
                                                        zip_sha256=zip_digest, source_name=path.name)))
            status, diagnostics = 'NO_EVTX', {}
            if members:
                try:
                    dist = verify_engine(engine, engine_root)
                except (OSError, ValueError) as exc:
                    status, diagnostics = 'ENGINE_UNAVAILABLE', {'error': str(exc)}
                else:
                    file_results = []
                    deadline = time.monotonic() + PARAMETERS['run_timeout_seconds']
                    for index, info in enumerate(members):
                        file_work = work / f'file-{index:02d}'
                        file_work.mkdir(mode=0o700)
                        source = file_work / 'source.evtx'
                        with archive.open(info) as stream:
                            copy_bounded(stream, source, MAX_EVTX)
                        digest = sha256_file(source)
                        remaining = deadline - time.monotonic()
                        result = (run_worker(source, dist, engine, digest, file_work, min(120, remaining))
                                  if remaining > 0 else {'status': 'TIMEOUT'})
                        if sha256_file(source) != digest:
                            result = {'status': 'INPUT_CHANGED'}
                        with db:
                            persist_file(db, run_id, collection_id, zip_digest, info.filename,
                                         digest, info.file_size, result)
                        file_results.append(result['status'])
                    verify_engine(engine, engine_root)
                    if any(s not in SUCCESS for s in file_results):
                        status = 'PARTIAL_FAILURE' if any(s in SUCCESS for s in file_results) else 'FAILED'
                    else:
                        status = 'MATCHES' if 'MATCHES' in file_results else 'NO_RULE_MATCHES'
                        unresolved = db.execute("SELECT count(*) FROM analysis_findings WHERE run_id=? AND reference_status='AGGREGATE_UNRESOLVED'", (run_id,)).fetchone()[0]
                        if unresolved:
                            status = 'UNRESOLVED'
            with db:
                db.execute('UPDATE analysis_runs SET status=?,finished_at_utc=?,diagnostics_json=? WHERE id=?',
                           (status, utcnow(), canonical(diagnostics), run_id))
            result = get_run(db, run_id)
            (work / 'summary.json').write_text(canonical(result))
            return result
        except BaseException:
            if 'run_id' in locals():
                with db:
                    db.execute("UPDATE analysis_runs SET status='INTERRUPTED',finished_at_utc=? WHERE id=? AND status='RUNNING'",
                               (utcnow(), run_id))
            raise
        finally:
            db.close()
