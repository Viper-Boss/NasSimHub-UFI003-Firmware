#!/usr/bin/env python3
"""Fail closed on sensitive artifact classes. Reports paths only, never matching values."""
import pathlib, re, sys
root = pathlib.Path(__file__).resolve().parents[1]
patterns = [r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
 r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}',
 r'(?i)(?:password|passwd|psk|token)\s*[:=]\s*["\']?[^\s"\']{8,}',
 r'(?:C:|D:|F:|G:)[/\\](?:Users|Claude)[/\\][^\s]+']
# Assignment names and synthetic examples require human review; avoid matching code variables.
strong = [re.compile(p) for p in patterns[:2] + patterns[3:]]
forbidden = {'.img','.dtb','.ko','.pem','.key','.pcap','.mp3','.wav','.zip','.7z','.deb','.exe'}
bad=[]
for p in root.rglob('*'):
 if not p.is_file() or any(x in {'.git','build','dist','downloads','private','__pycache__'} for x in p.relative_to(root).parts): continue
 if p.suffix.lower() in forbidden or p.name in {'device.json','admin-bootstrap.txt'} or '.bak' in p.name: bad.append(str(p.relative_to(root))); continue
 text=p.read_text(encoding='utf-8')
 if any(rx.search(text) for rx in strong): bad.append(str(p.relative_to(root)))
if bad:
 print('Privacy check FAILED, review files:'); print('\n'.join(sorted(set(bad)))); sys.exit(1)
print('Privacy artifact/token check PASS; manual personal-data review remains required.')
