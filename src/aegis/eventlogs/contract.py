"""EVTX decoding and strict Hayabusa 3.3 output references, established in M5."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
from unittest.mock import patch
import xml.etree.ElementTree as ET

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
ANSI = re.compile(r'\x1b\[[0-9;]*m')
EXPECTED_RULE = 'c03c42ba-1e4e-45c3-c0ba-c8d38b077ee7'
REQUIRED_FIELDS = {'Timestamp', 'RuleID', 'RuleTitle', 'RuleAuthor', 'Level', 'Computer',
                   'Channel', 'EventID', 'RecordID', 'EvtxFile'}


def precise_filetime(ticks: int) -> datetime:
    # python-evtx 0.8.1 uses float(ticks)*1e-7, losing up to microseconds.
    # Preserve integer arithmetic; both outputs have microsecond precision.
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)


def read_events(path: Path, max_events: int = 100000) -> tuple[list[dict], dict]:
    from Evtx.Evtx import Evtx
    if path.stat().st_size < 4096:
        raise ValueError('Input is shorter than an EVTX file header')
    with path.open('rb') as stream:
        if stream.read(8) != b'ElfFile\x00':
            raise ValueError('Missing EVTX file signature')
    events = []
    with patch('Evtx.BinaryParser.parse_filetime', precise_filetime), Evtx(str(path)) as log:
        header = log.get_file_header()
        version = (header.major_version(), header.minor_version())
        # python-evtx 0.8.1 header.verify() only admits 3.1. The Windows-generated
        # 3.2 baseline has valid header/chunk CRCs and independently readable rows.
        if version not in ((3, 1), (3, 2)) or header.header_chunk_size() != 4096:
            raise ValueError(f'Unsupported EVTX header version/layout: {version}')
        if header.checksum() != header.calculate_checksum():
            raise ValueError('EVTX header checksum mismatch')
        chunks = list(log.chunks())
        if not all(chunk.verify() for chunk in chunks):
            raise ValueError('EVTX chunk checksum mismatch')
        for record in log.records():
            if len(events) >= max_events:
                raise ValueError('EVTX event count limit exceeded')
            xml = record.xml()
            system = ET.fromstring(xml).find('e:System', NS)
            if system is None:
                raise ValueError('Event has no System metadata')
            item = {key: system.findtext('e:' + key, namespaces=NS)
                    for key in ('EventID', 'EventRecordID', 'Channel', 'Computer')}
            item.update(timestamp=system.find('e:TimeCreated', NS).attrib['SystemTime'],
                        byte_offset=record.offset(), xml=xml)
            events.append(item)
    return events, {'header_version': '.'.join(map(str, version)), 'chunks': len(chunks),
                    'header_crc_valid': True, 'chunk_crcs_valid': True}


def classify(exit_code: int, timed_out: bool, input_error: str | None,
             diagnostics: str, output_exists: bool, record_count: int, finding_count: int) -> str:
    if timed_out:
        return 'TIMEOUT'
    if input_error:
        return 'INVALID_EVIDENCE'
    engine_error = ('Errors were generated' in diagnostics or '[ERROR]' in diagnostics or
                    re.search(r'Rule parsing errors:\s*[1-9]', diagnostics))
    if exit_code != 0 or engine_error or not output_exists:
        return 'ENGINE_ERROR'
    if record_count == 0:
        return 'NO_READABLE_EVENTS'
    return 'MATCHES' if finding_count else 'NO_RULE_MATCHES'


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def link_finding(finding: dict, events: list[dict], source: Path, digest: str) -> dict:
    missing = REQUIRED_FIELDS - finding.keys()
    if missing:
        raise ValueError(f'Unexpected output contract, missing fields: {sorted(missing)}')
    if Path(finding['EvtxFile']).resolve() != source.resolve():
        raise ValueError('Finding references a different EVTX file')
    if finding['RecordID'] == '-':
        return {'status': 'AGGREGATE_UNRESOLVED', 'evidence_refs': []}
    matches = [e for e in events if e['EventRecordID'] == str(finding['RecordID'])
               and e['Channel'] == finding['Channel'] and e['Computer'] == finding['Computer']
               and e['EventID'] == str(finding['EventID'])
               and instant(e['timestamp']) == instant(finding['Timestamp'])]
    if len(matches) != 1:
        raise ValueError('Event reference is absent or ambiguous')
    event = matches[0]
    # Proposed M6 identifier includes original file bytes and record offset.
    evidence_id = hashlib.sha256(f"{digest}\0{event['byte_offset']}".encode()).hexdigest()
    return {'status': 'VERIFIED_SINGLE_EVENT', 'evidence_refs': [
        {'proposed_evidence_id': evidence_id, 'source_sha256': digest,
         'record_id': event['EventRecordID'], 'byte_offset': event['byte_offset'],
         'channel': event['Channel'], 'computer': event['Computer'],
         'event_id': event['EventID'], 'timestamp': event['timestamp'],
         'timestamp_delta_us': round((instant(event['timestamp']) - instant(finding['Timestamp'])).total_seconds() * 1_000_000)}]}

