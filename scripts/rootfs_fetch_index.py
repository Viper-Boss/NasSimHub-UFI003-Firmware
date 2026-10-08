#!/usr/bin/env python3
"""Fetch and check one `Packages` index of a pinned Debian archive snapshot.

    rootfs_fetch_index.py --base URL --suite trixie --arch arm64 [--component main]
                          --keyring /usr/share/keyrings/debian-archive-keyring.gpg
                          --out-packages FILE --out-release FILE [--test-unsigned]

Used ONLY by `build-rootfs.sh --lock`, on a networked build host. It is the
one script of the rootfs build that talks to the network, and it is kept apart
from scripts/rootfs_tools.py so that nothing a build runs can download.

What is checked: the InRelease file's OpenPGP signature (with gpgv and the
Debian archive keyring), then the SHA-256 and size of the Packages file against
that InRelease. An index that fails either check is not written.

--test-unsigned skips the signature check. It exists for the offline unit test
(a hand-written fixture archive read through file://); the caller then marks
the lock as a test fixture, which no release build accepts.
"""
import argparse
import gzip
import hashlib
import http.client
import lzma
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rootfs_tools  # noqa: E402

LIMIT = 256 << 20


def fetch(url):
    if not url.startswith(('https://', 'http://', 'file://')):
        raise rootfs_tools.BuildError(f'unsupported URL {url}')
    # A bounded read can return a truncated body without IncompleteRead. Never
    # hand that body to the signature/hash checker; retry transport failures.
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
                expected = response.headers.get('Content-Length')
                expected = int(expected) if expected is not None else None
                if expected is not None and expected > LIMIT:
                    raise rootfs_tools.BuildError(f'{url} is larger than {LIMIT} bytes')
                chunks, total = [], 0
                while True:
                    chunk = response.read(min(1 << 20, LIMIT + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > LIMIT:
                        raise rootfs_tools.BuildError(f'{url} is larger than {LIMIT} bytes')
                if expected is not None and total != expected:
                    raise http.client.IncompleteRead(b'', expected - total)
                return b''.join(chunks)
        except (OSError, urllib.error.URLError, http.client.IncompleteRead) as error:
            if attempt == 2:
                raise rootfs_tools.BuildError(f'{url}: download failed after 3 attempts ({error})') from error
            time.sleep(attempt + 1)


def verify_signature(inrelease, keyring):
    """gpgv over the clearsigned InRelease; raises unless it verifies."""
    if not os.path.isfile(keyring):
        raise rootfs_tools.BuildError(f'keyring {keyring} not found (install debian-archive-keyring)')
    with tempfile.NamedTemporaryFile(suffix='.InRelease') as handle:
        handle.write(inrelease)
        handle.flush()
        try:
            result = subprocess.run(['gpgv', '--keyring', keyring, handle.name], capture_output=True, text=True)
        except FileNotFoundError:
            raise rootfs_tools.BuildError('gpgv not found (install gpgv)')
    if result.returncode != 0:
        raise rootfs_tools.BuildError('the InRelease signature does not verify with the Debian archive keyring:\n' + result.stderr.strip())


def index(base, suite, arch, component, keyring, unsigned=False):
    """(Packages text, InRelease text) for one suite of one archive."""
    base = base.rstrip('/') + '/'
    inrelease = fetch(f'{base}dists/{suite}/InRelease')
    if not unsigned:
        verify_signature(inrelease, keyring)
    hashes = rootfs_tools.release_hashes(inrelease.decode('utf-8', 'replace'))
    for suffix, opener in (('.xz', lzma.decompress), ('.gz', gzip.decompress), ('', bytes)):
        relative = f'{component}/binary-{arch}/Packages{suffix}'
        if relative not in hashes:
            continue
        data = fetch(f'{base}dists/{suite}/{relative}')
        digest, size = hashes[relative]
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise rootfs_tools.BuildError(f'{relative} of {suite} does not match its InRelease entry')
        return opener(data).decode('utf-8'), inrelease.decode('utf-8', 'replace')
    raise rootfs_tools.BuildError(f'InRelease of {suite} lists no {component}/binary-{arch}/Packages')


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base', required=True)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--arch', required=True)
    parser.add_argument('--component', default='main')
    parser.add_argument('--keyring', default='/usr/share/keyrings/debian-archive-keyring.gpg')
    parser.add_argument('--out-packages', required=True)
    parser.add_argument('--out-release', required=True)
    parser.add_argument('--test-unsigned', action='store_true')
    arguments = parser.parse_args(argv)
    try:
        packages, release = index(arguments.base, arguments.suite, arguments.arch, arguments.component, arguments.keyring,
                                  arguments.test_unsigned)
    except (rootfs_tools.BuildError, OSError, lzma.LZMAError) as error:
        print(f'rootfs_fetch_index: {error}', file=sys.stderr)
        return 1
    pathlib.Path(arguments.out_packages).write_text(packages)
    pathlib.Path(arguments.out_release).write_text(release)
    print(f'{arguments.suite}: Packages index verified against InRelease' + (' (SIGNATURE NOT CHECKED: test mode)' if arguments.test_unsigned else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
