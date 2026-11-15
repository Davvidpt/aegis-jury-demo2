"""Resource-bounded subprocess worker. Never called inside the dashboard process."""
import argparse
import json
from pathlib import Path
import resource
import subprocess
import time
from importlib.metadata import version

from .contract import ANSI, classify, link_finding, read_events


def execute(source: Path, dist: Path, binary: str, digest: str, work: Path):
    result = {'status': 'INVALID_EVIDENCE', 'events': [], 'findings': [], 'references': []}
    try:
        decoder_version = version('python-evtx')
        if decoder_version != '0.8.1':
            return result | {'status': 'DEPENDENCY_UNSUPPORTED', 'decoder_version': decoder_version}
        events, validation = read_events(source)
    except ImportError:
        return result | {'status': 'DEPENDENCY_MISSING', 'error': 'Install .[m6] for python-evtx'}
    except Exception as exc:
        return result | {'error': str(exc), 'error_type': type(exc).__name__}
    result.update(events=events, input_validation=validation, decoder_version=decoder_version)
    if not events:
        return result | {'status': 'NO_READABLE_EVENTS'}
    (work / 'config').symlink_to(dist / 'config', target_is_directory=True)
    output = work / 'timeline.jsonl'
    command = [str(dist / binary), 'json-timeline', '-f', str(source),
               '-r', str(dist / 'rules'), '-c', str(dist / 'rules/config'),
               '-p', 'super-verbose', '-L', '-O', '-b', '-w', '-m', 'medium',
               '-t', '1', '-K', '-q', '-o', str(output)]
    (work / 'command.json').write_text(json.dumps(command))
    start = time.monotonic()
    try:
        with (work / 'stdout.txt').open('w') as out, (work / 'stderr.txt').open('w') as err:
            proc = subprocess.run(command, cwd=work, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err, timeout=90, check=False)
    except subprocess.TimeoutExpired:
        return result | {'status': 'TIMEOUT'}
    except OSError as exc:
        return result | {'status': 'ENGINE_UNAVAILABLE', 'error': str(exc)}
    result.update(exit_code=proc.returncode, duration_seconds=round(time.monotonic() - start, 4),
                  peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    diagnostics = ANSI.sub('', (work / 'stdout.txt').read_text(errors='replace') +
                           (work / 'stderr.txt').read_text(errors='replace'))
    result['status'] = classify(proc.returncode, False, None, diagnostics, output.exists(), len(events), 0)
    if result['status'] != 'NO_RULE_MATCHES':
        return result
    import re
    match = re.search(r'Events with hits\s*/\s*Total events:\s*[\d,]+\s*/\s*([\d,]+)', diagnostics)
    if not match or int(match[1].replace(',', '')) != len(events):
        return result | {'status': 'EVENT_COUNT_MISMATCH'}
    try:
        findings = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
        references = [link_finding(f, events, source, digest) for f in findings]
    except (ValueError, KeyError, TypeError) as exc:
        return result | {'status': 'OUTPUT_ERROR', 'error': str(exc)}
    return result | {'status': 'MATCHES' if findings else 'NO_RULE_MATCHES',
                     'findings': findings, 'references': references}


def main():
    parser = argparse.ArgumentParser()
    for flag in ('source', 'dist', 'binary', 'digest', 'work'):
        parser.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    # Linux worker and its engine child share these limits. The parent also
    # bounds elapsed time and kills the entire process group on timeout.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    work = Path(args.work)
    result = execute(Path(args.source), Path(args.dist), args.binary, args.digest, work)
    (work / 'result.json').write_text(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
