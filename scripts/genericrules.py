"""Rules that keep a factory package, an OTA release and a rootfs GENERIC.

A generic artifact is one that may be flashed onto, or sent to, any device of
the board type. It therefore must not carry anything that belongs to one device
or one person: device identity, pairing state, an administrator password or
its hash, Wi-Fi credentials, SSH host keys or somebody's authorized_keys,
device certificates or private keys, modem NV/EFS/calibration data
(modemst1/modemst2/fsg/fsc/persist), IMEI/IMSI/ICCID/phone numbers, logs, SMS.

Shared by scripts/privacy-check.py (package and release output) and
scripts/audit-rootfs.py (the rootfs tree before it becomes an image).

Every finding is (category, path). The matching VALUE is never returned or
printed: a checker that echoes the secret it found has just leaked it into a
build log.

What these rules are not: proof that an image is clean. They catch the known
file names the agent writes (see docs/FIRST_BOOT.md), well-known key formats,
keyword-labelled identifiers and secret-shaped tokens. A 64-digit hex secret is
indistinguishable from a checksum and passes; an IMEI with no label next to it
passes. Manual review stays required and the scripts say so.
"""
import base64
import hashlib
import json
import math
import os
import pathlib
import re
import stat

# --- file names -------------------------------------------------------------

# Files the agent creates in its state directory on first start. The names come
# from node/agent: internal/identity (device.json), internal/pqidentity
# (pq-identity.json), internal/pairing (pairing.json), internal/transportkey
# (transport-key.json), internal/localadmin (admin.json, admin-bootstrap.txt,
# admin-tls-*.pem), nodetls (device-cert.pem), modembackend/msm8916
# (sms-requests.json), ota (ota-state.json), netbackend/networkmanager
# (setup-ap-passphrase: the generated passphrase of the setup access point).
STATE_NAMES = {
    'device.json': 'device-identity',
    'pq-identity.json': 'device-identity',
    'pairing.json': 'pairing-state',
    'transport-key.json': 'pairing-state',
    'admin.json': 'admin-password',
    'admin-bootstrap.txt': 'admin-password',
    'device-cert.pem': 'device-certificate',
    'admin-tls-key.pem': 'device-certificate',
    'admin-tls-cert.pem': 'device-certificate',
    'sms-requests.json': 'sms',
    'ota-state.json': 'device-state',
    'setup-ap-passphrase': 'wifi-credential',
}
SSH_NAME = re.compile(r'^(?:ssh_host_.*key(?:\.pub)?|authorized_keys2?|id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?)$')
KEY_SUFFIXES = ('.key', '.pem', '.p12', '.pfx', '.ppk', '.jks', '.keystore')
# Per-device modem data. The names are the partitions (and the files rmtfs uses
# in place of them). Copying these between devices clones or destroys RF
# calibration and the IMEI; a generic package has no business containing them.
CALIBRATION_STEMS = {'modemst1', 'modemst2', 'fsg', 'fsc', 'persist',
                     'modem_fs1', 'modem_fs2', 'modem_fsg', 'modem_fsc'}
CALIBRATION_SUFFIXES = ('.qcn', '.xqcn', '.efs', '.nvm')
# Bootloader/TrustZone partitions: never written by this project, so never shipped.
BOOTCHAIN_STEMS = {'sbl1', 'aboot', 'tz', 'rpm', 'hyp', 'sec', 'cdt', 'gpt'}
_STRIP = ('.img', '.bin', '.mbn', '.raw', '.dump', '.bak', '.ext4', '.tar', '.gz', '.xz', '.zst', '.lz4', '.zip', '.7z')
LOG_NAME = re.compile(r'(?:\.log(?:\.\d+)?(?:\.gz|\.xz)?|\.journal~?|\.pcap(?:ng)?)$')
SMS_NAME = re.compile(r'^sms(?:[-_.].*)?\.(?:json|db|sqlite|txt|csv|xml)$')
WIFI_NAME = re.compile(r'(?:\.nmconnection|\.psk|\.8021x)$|^wpa_supplicant.*\.conf$')


def partition_stem(name):
    """`ModemST1.bin.gz` -> `modemst1`: the name with image/archive suffixes removed."""
    stem = name.lower()
    changed = True
    while changed:
        changed = False
        for suffix in _STRIP:
            if stem.endswith(suffix) and len(stem) > len(suffix):
                stem, changed = stem[:-len(suffix)], True
    return stem


def name_findings(name, package=True):
    """Categories a file is refused for on its name alone.

    package=True is the strict set for files this project puts into a package
    or a release. package=False is the set that is safe to apply to a whole
    Debian root filesystem, where `.pem` certificates and files that merely end
    in `.log` are ordinary; there the key CONTENT rules and the /var/log rule in
    audit-rootfs.py do that work instead.
    """
    found = []
    lower = name.lower()
    if lower in STATE_NAMES:
        found.append(STATE_NAMES[lower])
    if SSH_NAME.match(lower):
        found.append('ssh-key')
    if lower.endswith(('.ed25519.key', '.mldsa.key')):
        found.append('release-private-key')
    elif package and lower.endswith(KEY_SUFFIXES) and lower not in STATE_NAMES:
        found.append('key-file')
    stem = partition_stem(lower)
    if stem in CALIBRATION_STEMS or lower.endswith(CALIBRATION_SUFFIXES):
        found.append('modem-calibration')
    if SMS_NAME.match(lower):
        found.append('sms')
    if package:
        # The one connection profile the overlay ships is the USB link, which
        # has no secret; privacy-check.py also reads it to make sure.
        if WIFI_NAME.search(lower) and lower != 'nassimhub-usb.nmconnection':
            found.append('wifi-credential')
        if stem in BOOTCHAIN_STEMS:
            found.append('protected-partition')
        if LOG_NAME.search(lower):
            found.append('log')
        if lower.endswith(('.enabled', '.verified')):
            found.append('per-device-acceptance-marker')
        if lower in ('machine-id', 'random-seed'):
            found.append('device-identity')
        if lower.endswith(('.wav', '.mp3', '.amr', '.opus', '.pcm')):
            found.append('recording')
    return found


# --- content ----------------------------------------------------------------

# A PEM/OpenSSH private key WITH a body. The bare BEGIN line also occurs as a
# string constant inside ssh-keygen and similar programs; a key has base64 (or
# the legacy encryption header) on the next line, a constant does not.
PRIVATE_KEY_BLOCK = re.compile(
    rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]{24,}|Proc-Type:)')
PUTTY_KEY = re.compile(rb'PuTTY-User-Key-File-\d: ')
# nsh-release private key file (node/agent/cmd/nsh-release: keyFile.Kind).
RELEASE_PRIVATE_KEY = re.compile(rb'"kind"\s*:\s*"nassimhub-release-(?:ed25519|mldsa)"')
# device.json / pq-identity.json / nsh-release key bodies: a stored seed.
PRIVATE_SEED = re.compile(rb'"(?:private_seed|seed)"\s*:\s*"[A-Za-z0-9+/=_-]{40,}"')
BINARY_RULES = (
    ('private-key', PRIVATE_KEY_BLOCK),
    ('private-key', PUTTY_KEY),
    ('release-private-key', RELEASE_PRIVATE_KEY),
    ('device-identity', PRIVATE_SEED),
)

TEXT_RULES = (
    # internal/localadmin credentials: {"salt": ..., "hash": ...}
    ('admin-password', re.compile(r'"salt"\s*:\s*"[^"]{16,}"\s*,\s*"hash"\s*:\s*"[^"]{16,}"')),
    # crypt(3) hashes as found in shadow files and configuration.
    ('admin-password', re.compile(r'\$(?:1|5|6|y|2[aby]|argon2id?)\$[./A-Za-z0-9$=,+-]{20,}')),
    # NetworkManager keyfile / wpa_supplicant / hostapd assignments, and the
    # ifupdown `wpa-psk <value>` form.
    ('wifi-credential', re.compile(r'(?im)^\s*(?:psk|wpa_passphrase|sae[-_]password|wep[-_]key\d?)\s*=\s*\S+')),
    ('credential', re.compile(r'(?im)^\s*(?:password|passwd|passphrase)\s*=\s*\S+')),
    ('wifi-credential', re.compile(r'(?im)^\s*wpa-psk\s+\S+')),
    ('transport-secret', re.compile(r'"secret"\s*:\s*"[A-Za-z0-9+/=_-]{16,}"')),
    ('token', re.compile(r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}')),
    ('imei', re.compile(r'(?i)\bimei(?:sv)?\b\W{0,16}\d{14,16}\b')),
    ('imsi', re.compile(r'(?i)\bimsi\b\W{0,16}\d{14,15}\b')),
    ('iccid', re.compile(r'(?i)\biccid\b\W{0,16}\d{18,22}')),
    # ITU-T E.118: an ICCID starts with 89 and is 19 or 20 digits.
    ('iccid', re.compile(r'(?<![\w.])89\d{17,18}(?![\w.])')),
    ('phone-number', re.compile(r'(?i)\b(?:msisdn|phone(?:[ _-]?(?:number|no))?|own[ _-]?numbers?|tel)\b\W{0,16}\+?\d{7,15}\b')),
    ('phone-number', re.compile(r'(?:手机号|电话号码|本机号码)\W{0,16}\+?\d{7,15}')),
    # E.164 written without separators.
    ('phone-number', re.compile(r'(?<![\w.+-])\+[1-9]\d{9,14}(?![\w.])')),
    # proto.DeviceID: NSH-<platform short code>-<6 hex of the key hash>.
    ('device-identity', re.compile(r'\bNSH-[0-9A-Z]{2,6}-[0-9A-F]{6}\b')),
)

_TOKEN = re.compile(r'[A-Za-z0-9+/_-]{32,}={0,2}')
TEXT_LIMIT = 2 << 20


def shannon(value):
    counts = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def has_secret_like_token(text):
    """A long token that looks like base64 of random bytes.

    Hexadecimal digests (SHA256SUMS, manifests) top out at 4 bits per character
    and never mix upper and lower case, so they pass; a 32-byte secret in
    base64 measures about 5. Paths and identifiers are long but repetitive and
    single-case. The thresholds are a heuristic, not a proof.
    """
    for match in _TOKEN.finditer(text):
        token = match.group(0).rstrip('=')
        if not (any(c.islower() for c in token) and any(c.isupper() for c in token) and any(c.isdigit() for c in token)):
            continue
        if shannon(token) >= 4.5:
            return True
    return False


def scan_bytes(data):
    """Categories found in a whole small file's bytes (binary-safe rules only)."""
    return _scan_binary_window(data, BINARY_RULES)


_PUBLIC_SELFTEST_KEYS = frozenset(json.loads(
    pathlib.Path(__file__).with_name('public-selftest-keys.json').read_text())['der_sha256'])
_COMPLETE_PEM = re.compile(
    rb'-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----\s*(.*?)\s*-----END \1-----', re.S)


def _scan_binary_window(data, rules):
    found = set()
    for category, rule in rules:
        for match in rule.finditer(data):
            if rule is PRIVATE_KEY_BLOCK:
                full = _COMPLETE_PEM.match(data, match.start())
                if full:
                    try:
                        der = base64.b64decode(re.sub(rb'\s', b'', full.group(2)), validate=True)
                    except ValueError:
                        der = b''
                    if hashlib.sha256(der).hexdigest() in _PUBLIC_SELFTEST_KEYS:
                        continue
            found.add(category)
            break
    return sorted(found)


def scan_text(text, entropy=False):
    found = [category for category, rule in TEXT_RULES if rule.search(text)]
    if entropy and has_secret_like_token(text):
        found.append('high-entropy-secret-like-value')
    return found


def read_text(path, limit=TEXT_LIMIT):
    """The file as text, or None when it is large or not UTF-8 text."""
    try:
        if os.lstat(path).st_size > limit:
            return None
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return None
    if b'\0' in data:
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return None


def scan_stream(path, rules=BINARY_RULES, block=4 << 20, overlap=4096):
    """Search a file of any size (a filesystem image) for the binary rules.

    Blocks overlap so a match that straddles a block boundary is still seen.
    A raw ext4 image stores a small file's bytes contiguously, so a key file
    inside an image is found without mounting it. A compressed payload (the
    kernel in boot.img) is opaque to this scan.
    """
    found = set()
    tail = b''
    with open(path, 'rb') as handle:
        while True:
            data = handle.read(block)
            if not data:
                break
            window = tail + data
            found.update(_scan_binary_window(window, rules))
            tail = window[-overlap:]
    return sorted(found)


def is_opaque_blob(path):
    """A small non-text file: the shape of a raw key or an exported secret."""
    try:
        size = os.lstat(path).st_size
        if not 16 <= size <= 8192:
            return False
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return False
    if b'\0' not in data:
        try:
            data.decode('utf-8')
            return False
        except UnicodeDecodeError:
            pass
    return True


# --- the public release keyring ---------------------------------------------

_KEY_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
# ML-DSA public key sizes (FIPS 204).
_MLDSA_PUBLIC = {'ml-dsa-65': 1952, 'ml-dsa-87': 2592}


def public_keyring_problem(raw):
    """None when raw is a release PUBLIC key file, else the reason it is not.

    Mirrors proto.ParseOTAKeyFile (node/proto/ota_keyfile.go): version 1, an
    `ed25519` map of key id -> base64 32-byte key, an optional `ml_dsa` map, and
    NO other field. The private key files nsh-release writes have `kind` and
    `seed` fields and are refused by that last rule.

    A 32-byte Ed25519 public key and a 32-byte private seed have the same
    shape, so this cannot tell a keyring that someone filled with seeds from a
    real one. `nsh-release keyring` is the only supported way to produce it.
    """
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return 'not JSON'
    if not isinstance(document, dict):
        return 'not a JSON object'
    extra = set(document) - {'version', 'ed25519', 'ml_dsa'}
    if extra:
        return 'has fields a public keyring never has: ' + ', '.join(sorted(extra))
    if document.get('version') != 1:
        return 'unsupported version'
    classical = document.get('ed25519')
    if not isinstance(classical, dict) or not classical:
        return 'holds no ed25519 release key'
    for key_id, encoded in classical.items():
        if not _KEY_ID.match(key_id) or not isinstance(encoded, str):
            return 'has an unusable ed25519 entry'
        try:
            if len(base64.b64decode(encoded, validate=True)) != 32:
                return 'has an ed25519 entry that is not a 32-byte key'
        except ValueError:
            return 'has an ed25519 entry that is not base64'
    post_quantum = document.get('ml_dsa', {})
    if not isinstance(post_quantum, dict):
        return 'has an unusable ml_dsa section'
    for key_id, identity in post_quantum.items():
        if not _KEY_ID.match(key_id) or not isinstance(identity, dict) or set(identity) != {'algorithm', 'public_key'}:
            return 'has an unusable ml_dsa entry'
        size = _MLDSA_PUBLIC.get(identity['algorithm'])
        try:
            if size is None or len(base64.b64decode(identity['public_key'], validate=True)) != size:
                return 'has an ml_dsa entry that is not a public key of its algorithm'
        except (ValueError, TypeError):
            return 'has an ml_dsa entry that is not base64'
    return None


def keyring_counts(raw):
    document = json.loads(raw)
    return len(document.get('ed25519', {})), len(document.get('ml_dsa', {}))


def is_signed_manifest(raw):
    """A signed OTA manifest: public by design, although it is full of base64."""
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return False
    allowed = {'manifest', 'key_id', 'signature', 'pq_signature', 'pq_key_id', 'pq_algorithm'}
    return (isinstance(document, dict) and {'manifest', 'key_id', 'signature'} <= set(document) <= allowed
            and isinstance(document['manifest'], dict))


def walk_files(root):
    """Every non-directory under root as (absolute, relative posix path, lstat).

    Symbolic links are reported, never followed: a link in an untrusted rootfs
    may point anywhere on the build host.
    """
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        for name in sorted(files) + [n for n in names if os.path.islink(os.path.join(directory, n))]:
            absolute = os.path.join(directory, name)
            yield absolute, os.path.relpath(absolute, root).replace(os.sep, '/'), os.lstat(absolute)


def is_regular(info):
    return stat.S_ISREG(info.st_mode)
