#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
p = subprocess.run([sys.executable, str(HERE / 'miweb.py'), '--self-test', '--compact'], capture_output=True, text=True, check=True)
r = json.loads(p.stdout)
assert r['schema'] == 'desarrollamo.miweb.v1'
assert r['self_test'] is True
assert r['seo']['title'] == 'Demo'
assert r['seo']['h1_count'] == 1
assert r['seo']['images_without_alt'] == 0
print('MiWeb schema OK')
