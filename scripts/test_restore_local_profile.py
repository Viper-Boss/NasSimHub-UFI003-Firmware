import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).parent / 'restore-local-profile.sh'
with tempfile.TemporaryDirectory() as temp:
    top = Path(temp)
    root = top / 'offline'
    (root / 'etc/nassimhub').mkdir(parents=True)
    base = top / 'private'
    base.mkdir(mode=0o700)
    names = ['etc/nassimhub/agent.conf', 'etc/nassimhub/voice-audio.verified']
    for name in ('ims', 'radio'):
        names.extend(f'etc/systemd/system/nassimhub-{name}-status.{suffix}' for suffix in ('timer', 'service'))
    for name in names:
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('test fixture\n')
        path.chmod(0o600)
    (base / 'SHA256SUMS').write_text(''.join(hashlib.sha256((base / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names))
    (base / 'MODES').write_text(''.join('644 ' + name + '\n' for name in names))
    for name in ('SHA256SUMS', 'MODES'):
        (base / name).chmod(0o600)
    script = top / 'restore'
    # Only mount plumbing and fixed installed state path change in the sandbox.
    text = source.read_text().replace('/var/lib/nassimhub/.private-system', str(base))
    text = text.replace('/usr/local/libexec/nassimhub-state-check', 'true')
    text = text.replace('[ "$(findmnt -n -o TARGET --target "$root")" = "$root" ]', 'true')
    text = text.replace('[ "$(findmnt -n -o FSTYPE --target "$root")" = ext4 ]', 'true')
    text = text.replace('[ "$(findmnt -n -o LABEL --target "$root")" = rootfs ]', 'true')
    text = text.replace('[ "$(findmnt -n -o MAJ:MIN --target "$root")" != "$(findmnt -n -o MAJ:MIN --target /)" ]', 'true')
    script.write_text(text)
    def run():
        return subprocess.run(['sh', str(script), str(root)], capture_output=True, text=True)
    (base / names[0]).write_text('tampered')
    assert run().returncode != 0
    assert not (root / names[0]).exists()
    (base / names[0]).write_text('test fixture\n')
    result = run()
    assert result.returncode == 0, result.stderr
    for name in names:
        assert (root / name).read_bytes() == (base / name).read_bytes()
    for name in ('ims', 'radio'):
        assert (root / f'etc/systemd/system/timers.target.wants/nassimhub-{name}-status.timer').is_symlink()
    (base / 'MODES').write_text((base / 'MODES').read_text().replace('644', '777'))
    (root / names[0]).write_text('unchanged')
    assert run().returncode != 0
    assert (root / names[0]).read_text() == 'unchanged'
    print('Restore sandbox: corruption refused before writes, exact files/timers restored, invalid modes refused.')
