#!/usr/bin/env python3
"""Reject populated device state before packaging; never print secret content."""
import pathlib, sys
root=pathlib.Path(sys.argv[1]).resolve()
bad=[]
for location in ('var/lib/nassimhub','var/lib/NetworkManager','root/.ssh','root/.config','home'):
 p=root/location
 if p.exists() and any(p.rglob('*')): bad.append(location)
for pattern in ('etc/ssh/ssh_host_*_key*','etc/NetworkManager/system-connections/*','etc/nassimhub/*.enabled','etc/nassimhub/*.verified','root/.*history','var/log/*'):
 for p in root.glob(pattern):
  if p.name=='nassimhub-usb.nmconnection' and p.is_file() and 'psk=' not in p.read_text(): continue
  if p.is_file() and p.stat().st_size: bad.append(str(p.relative_to(root)))
p=root/'etc/machine-id'
if p.exists() and p.read_text().strip(): bad.append('etc/machine-id')
if not (root/'etc/os-release').is_file() or 'VERSION_ID="13"' not in (root/'etc/os-release').read_text(): bad.append('expected Debian 13 os-release')
passwd=(root/'etc/passwd').read_text() if (root/'etc/passwd').exists() else ''
if not any(line.startswith('nassimhub:') and line.split(':')[2]!='0' for line in passwd.splitlines()): bad.append('missing non-root nassimhub account')
shadow=(root/'etc/shadow').read_text() if (root/'etc/shadow').exists() else ''
for line in shadow.splitlines():
 fields=line.split(':')
 if len(fields)>1 and not fields[1].startswith(('!','*')): bad.append('unlocked account/password in etc/shadow'); break
if bad:
 print('Clean rootfs audit FAILED:'); print('\n'.join(sorted(set(bad)))); sys.exit(1)
print('Clean rootfs state/account audit PASS')
