"""Acquire only pinned passive PCAP/label/readme data from the publisher."""
from pathlib import Path
import hashlib
import json
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]

def main(plan_path=None):
    plan_path = plan_path or ROOT / 'datasets/iot23_pilot_sources.json'
    plan = json.loads(plan_path.read_text())
    out = ROOT / 'data/raw/iot23'
    out.mkdir(parents=True, exist_ok=True)
    records = []
    for capture in plan['captures']:
        folder = out / capture['id']; folder.mkdir(exist_ok=True)
        for suffix, name in [('pcap/', capture['pcap']), ('', capture['labels']), ('', 'README.md')]:
            url = plan['base_url'] + capture['id'] + '/' + suffix + name
            dest = folder / name
            if not dest.exists():
                temp = dest.with_suffix(dest.suffix + '.partial')
                subprocess.run(['curl','--fail','--location','--silent','--show-error','--connect-timeout','20','--max-time','600','--max-filesize','450000000','--output',str(temp),url],check=True)
                temp.rename(dest)
            digest = hashlib.file_digest(dest.open('rb'), 'sha256').hexdigest()
            records.append({'url': url, 'path': str(dest.relative_to(ROOT)), 'bytes': dest.stat().st_size, 'sha256': digest, 'partition': capture['partition']})
            print(capture['id'], name, dest.stat().st_size, flush=True)
    (out/('acquisition.json' if plan_path.name == 'iot23_pilot_sources.json' else plan_path.stem + '-acquisition.json')).write_text(json.dumps({'acquired_at':datetime.now(timezone.utc).isoformat(), 'files':records, 'publisher_checksums_available':False},indent=2)+'\n')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', type=Path)
    main(parser.parse_args().plan)
