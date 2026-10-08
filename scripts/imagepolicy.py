#!/usr/bin/env python3
"""What the image may grant the agent, and the opt-in setup access point.

    imagepolicy.py enable-setup-ap AGENT_CONF   rewrite a COPY of the default configuration
    imagepolicy.py require-dnsmasq ROOTFS_DIR   fail early when the input rootfs lacks dnsmasq
    imagepolicy.py actions                      print the documented polkit grants

Shared by scripts/audit-rootfs.py (the staged tree), scripts/privacy-check.py
(the finished package) and scripts/package-factory.sh.

Three things in a root filesystem decide what the unprivileged agent user can
do beyond reading and writing its own files: the polkit rules written for it,
the capabilities its systemd unit hands it, and system-wide sysctls that lower
a privilege boundary for everybody. Each is held here to a documented list, so
a change to any of them has to be made in this file, where it is reviewed, and
not only in an overlay directory.

The setup access point needs one more polkit action and one capability
(docs/RELEASING.md section 11). Those two files are the fragment
firmware/setup-ap-overlay/ and are accepted only when the packager was asked
for them with NSH_SETUP_AP=on; the default is off, like `provisioning_ap = off`
in the shipped configuration.

What this is not: an interpreter for polkit's JavaScript. A rule file written
for the agent user must have one of the two shapes the overlay uses; anything
else is reported as unrecognised instead of being guessed at. Rules that do
not mention the agent user (Debian's own) are not examined.
"""
import json
import os
import re
import stat
import sys

sys.dont_write_bytecode = True

AGENT_USER = 'nassimhub'
NM = 'org.freedesktop.NetworkManager.'

# --- polkit -----------------------------------------------------------------

# Every action a rule may grant the agent user, per file, with the reason.
# Granting an action that is not listed for its file fails the audit.
BASE_POLKIT = {
    'etc/polkit-1/rules.d/49-nassimhub-networkmanager.rules': {
        NM + 'network-control': 'activate and deactivate a connection (join a network, go back to the saved one)',
        NM + 'settings.modify.system': 'add, change and delete the system connection profiles the agent owns',
        NM + 'wifi.scan': 'ask for a scan',
    },
    'etc/polkit-1/rules.d/50-nassimhub-modemmanager-messaging.rules': {
        'org.freedesktop.ModemManager1.Messaging': 'list, send and delete SMS through ModemManager',
    },
}
SETUP_AP_POLKIT_FILE = 'etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules'
SETUP_AP_POLKIT = {
    SETUP_AP_POLKIT_FILE: {
        NM + 'wifi.share.protected': 'activate a Wi-Fi profile with ipv4.method shared and wireless security (the setup access point)',
    },
}
# Never granted to the agent, switch or no switch, so the table above cannot be
# widened to them by a careless edit without a test failing: an open access
# point, and the actions that turn networking or radios off for the whole
# device.
NEVER_GRANTED = {NM + 'wifi.share.open', NM + 'enable-disable-network', NM + 'enable-disable-wifi',
                 NM + 'enable-disable-wwan', NM + 'settings.modify.global-dns', NM + 'settings.modify.hostname',
                 NM + 'reload', NM + 'checkpoint-rollback'}
POLKIT_DIRS = ('etc/polkit-1/rules.d/', 'usr/share/polkit-1/rules.d/', 'usr/local/share/polkit-1/rules.d/')

_ID = r'[A-Za-z0-9][A-Za-z0-9._-]*'
_RULE = re.compile(
    r'polkit\.addRule\(function\(action,subject\)\{'
    r'(?:varallowed=\[(?P<list>"' + _ID + r'"(?:,"' + _ID + r'")*)\];'
    r'if\(subject\.user==="(?P<user_a>' + _ID + r')"&&allowed\.indexOf\(action\.id\)>=0\)'
    r'|if\(subject\.user==="(?P<user_b>' + _ID + r')"&&action\.id==="(?P<single>' + _ID + r')"\))'
    r'\{returnpolkit\.Result\.YES;\}\}\);')


def polkit_grant(text):
    """(user, set of action ids) granted by a rule file, or None.

    None means the file is not, in its entirety, a sequence of rules of the two
    shapes the overlay uses: `subject.user === U && action.id === A` and
    `subject.user === U && [A, B, ...].indexOf(action.id) >= 0`, each returning
    polkit.Result.YES. A prefix match, a group test, a rule with no user test,
    a regular expression or any other construct is None: it may grant more
    than a list of names can express.
    """
    # Comments first. Action ids contain neither // nor /*, so a string
    # literal is never cut by this.
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    compact = re.sub(r'\s+', '', text)
    users, actions, position = set(), set(), 0
    while position < len(compact):
        match = _RULE.match(compact, position)
        if not match:
            return None
        users.add(match.group('user_a') or match.group('user_b'))
        if match.group('single'):
            actions.add(match.group('single'))
        else:
            actions.update(item.strip('"') for item in match.group('list').split(','))
        position = match.end()
    if len(users) != 1 or not actions:
        return None
    return users.pop(), actions


def documented_polkit(setup_ap):
    table = dict(BASE_POLKIT)
    if setup_ap:
        table.update(SETUP_AP_POLKIT)
    return table


def _read(path, limit=1 << 20):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit).decode('utf-8', 'replace')
    except OSError:
        return ''


def polkit_findings(files, setup_ap):
    """files: iterable of (absolute, relative, lstat) for the whole tree."""
    table = documented_polkit(setup_ap)
    findings = []
    for absolute, relative, info in files:
        if not relative.startswith(POLKIT_DIRS):
            continue
        regular = stat.S_ISREG(info.st_mode)
        text = _read(absolute) if regular else ''
        if AGENT_USER not in relative.rsplit('/', 1)[-1] and AGENT_USER not in text:
            continue
        if relative == SETUP_AP_POLKIT_FILE and not setup_ap:
            findings.append('setup-ap-file-without-switch: ' + relative)
            continue
        allowed = table.get(relative)
        if allowed is None or not regular:
            findings.append('polkit-rule-not-expected: ' + relative)
            continue
        grant = polkit_grant(text)
        if grant is None:
            findings.append('polkit-rule-unrecognised: ' + relative)
            continue
        user, actions = grant
        if user != AGENT_USER:
            findings.append('polkit-rule-for-another-user: ' + relative)
        # Action names are public identifiers, not secrets: naming the extra
        # one is what makes the finding usable.
        for action in sorted(actions - set(allowed)):
            findings.append(f'polkit-grants-undocumented-action: {relative} ({action})')
    return findings


# --- the agent's systemd unit -----------------------------------------------

UNIT_DIRS = ('etc/systemd/system/', 'usr/lib/systemd/system/', 'lib/systemd/system/')
AGENT_UNIT = 'nassimhub-agent.service'
# Drop-ins the image ships for the agent unit: firmware/overlay (persistent)
# and node/deploy/nassimhub-agent-resources.conf (resources). A voice drop-in
# is installed per device after acceptance, never in an image.
BASE_DROPINS = {'persistent.conf', 'resources.conf'}
SETUP_AP_DROPIN = 'setup-ap.conf'
SETUP_AP_DROPIN_FILE = 'etc/systemd/system/nassimhub-agent.service.d/' + SETUP_AP_DROPIN
SETUP_AP_CAPABILITIES = {'CAP_NET_BIND_SERVICE'}
SETUP_AP_FILES = (SETUP_AP_POLKIT_FILE, SETUP_AP_DROPIN_FILE)


def unit_settings(texts):
    """{(section, key): [values]} for a unit file followed by its drop-ins.

    systemd's rule for the settings looked at here: an empty assignment resets
    what came before, anything else is appended. For a setting that takes one
    value the last element is the effective one.
    """
    settings = {}
    for text in texts:
        section = ''
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in '#;':
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1]
                continue
            key, separator, value = line.partition('=')
            if not separator:
                continue
            key, value = key.strip(), value.strip()
            if value == '':
                settings[(section, key)] = []
            else:
                settings.setdefault((section, key), []).append(value)
    return settings


def last(settings, key, default='', section='Service'):
    values = settings.get((section, key))
    return values[-1] if values else default


def words(settings, key, section='Service'):
    return [word for value in settings.get((section, key), []) for word in value.split()]


def agent_unit_texts(root):
    """(texts, drop-in relative paths) of the agent unit in a tree, or (None, [])."""
    for directory in UNIT_DIRS:
        unit = os.path.join(root, directory, AGENT_UNIT)
        if os.path.isfile(unit) and not os.path.islink(unit):
            break
    else:
        return None, []
    texts, dropins = [_read(unit)], {}
    # A drop-in of the same name in /etc replaces the one in /usr/lib; they are
    # applied in name order whatever directory they come from.
    for directory in reversed(UNIT_DIRS):
        folder = os.path.join(root, directory, AGENT_UNIT + '.d')
        if os.path.isdir(folder) and not os.path.islink(folder):
            for name in os.listdir(folder):
                if name.endswith('.conf'):
                    dropins[name] = directory + AGENT_UNIT + '.d/' + name
    for name in sorted(dropins):
        texts.append(_read(os.path.join(root, dropins[name])))
    return texts, [dropins[name] for name in sorted(dropins)]


def unit_findings(root, setup_ap):
    texts, dropins = agent_unit_texts(root)
    if texts is None:
        return []  # A clean input rootfs has no agent unit yet.
    findings = []
    for relative in dropins:
        name = relative.rsplit('/', 1)[-1]
        if name == SETUP_AP_DROPIN and not setup_ap:
            findings.append('setup-ap-file-without-switch: ' + relative)
        elif name not in BASE_DROPINS and name != SETUP_AP_DROPIN:
            findings.append('agent-unit-drop-in-not-expected: ' + relative)
    settings = unit_settings(texts)
    expected = SETUP_AP_CAPABILITIES if setup_ap else set()
    for key in ('CapabilityBoundingSet', 'AmbientCapabilities'):
        if key == 'CapabilityBoundingSet' and ('Service', key) not in settings:
            # Never assigned means "every capability", not "none".
            findings.append('agent-unit-capabilities: CapabilityBoundingSet is not set')
            continue
        granted = words(settings, key)
        if any(word.startswith('~') for word in granted):
            findings.append(f'agent-unit-capabilities: {key} uses an inverted list')
        for capability in sorted(set(granted) - expected):
            findings.append(f'agent-unit-capabilities: {key} grants {capability}')
    if last(settings, 'User') in ('', 'root', '0'):
        findings.append('agent-unit-runs-as-root')
    if last(settings, 'NoNewPrivileges') not in ('yes', 'true', '1', 'on'):
        findings.append('agent-unit-capabilities: NoNewPrivileges is not set')
    return findings


# What each telemetry source the agent reads needs from the unit
# (node/agent/internal/systemstats). Used by the tests to notice when a synced
# unit starts hiding one; docs/VALIDATION.md has the directive-by-directive
# reasoning.
TELEMETRY_PATHS = ('/sys/class/thermal', '/sys/devices/system/cpu', '/sys/block/mmcblk0/device',
                   '/proc/net/dev', '/proc/stat', '/proc/meminfo', '/run/nassimhub-ims')


def telemetry_blockers(settings):
    """[(directive, what it hides)] for the effective [Service] settings."""
    blockers = []
    if last(settings, 'ProcSubset', 'all') == 'pid':
        blockers.append(('ProcSubset=pid', '/proc/net/dev, /proc/stat, /proc/meminfo, /proc/loadavg, /proc/cpuinfo'))
    protect_proc = last(settings, 'ProtectProc', 'default')
    if protect_proc != 'default':
        blockers.append(('ProtectProc=' + protect_proc, '/proc/<pid>/status of processes of other users (process count and memory)'))
    if last(settings, 'PrivateNetwork', 'no') in ('yes', 'true', '1', 'on'):
        blockers.append(('PrivateNetwork=yes', '/proc/net/dev lists only the loopback of a private network namespace'))
    for key in ('InaccessiblePaths', 'TemporaryFileSystem', 'BindPaths', 'BindReadOnlyPaths'):
        for word in words(settings, key):
            # Bind*: source[:destination[:options]], the destination is what is
            # covered. TemporaryFileSystem: path[:options].
            parts = word.lstrip('-+').split(':')
            path = (parts[1] if key.startswith('Bind') and len(parts) > 1 else parts[0]).rstrip('/')
            for wanted in TELEMETRY_PATHS:
                if wanted == path or wanted.startswith(path + '/') or path.startswith(wanted + '/'):
                    blockers.append((f'{key}={word}', wanted))
    return blockers


# --- sysctl -----------------------------------------------------------------

SYSCTL_FILES = re.compile(r'^(?:etc/sysctl\.conf|(?:etc|usr/lib|lib|usr/local/lib)/sysctl\.d/[^/]+\.conf)$')
_PORT_START = re.compile(r'(?m)^\s*-?\s*net[./]ipv4[./]ip_unprivileged_port_start\s*=')


def sysctl_findings(files):
    # Lowering this lets EVERY user bind the ports from the new value up to
    # 1023. The setup page gets port 80 through one capability on one service
    # instead; nothing in an image should be doing it this way.
    return ['unprivileged-port-sysctl: ' + relative for absolute, relative, info in files
            if SYSCTL_FILES.match(relative) and stat.S_ISREG(info.st_mode) and _PORT_START.search(_read(absolute))]


# --- the setup access point as a whole --------------------------------------

STATUS_OFF = 'setup access point: not enabled'
STATUS_ON = 'setup access point: enabled (not verified on hardware)'
AGENT_CONF = 'etc/nassimhub/agent.conf'
# NetworkManager's shared mode starts the dnsmasq binary for DHCP; Debian ships
# it in dnsmasq-base (firmware/debian-packages.json).
DNSMASQ = 'usr/sbin/dnsmasq'
_SETTING = r'(?m)^[ \t]*%s[ \t]*=[ \t]*(\S*)[ \t]*$'


def conf_value(text, key):
    values = re.findall(_SETTING % re.escape(key), text)
    return values[-1].lower() if values else None


def conf_enables_setup_ap(text):
    """The agent offers the access point only with BOTH keys set this way
    (node/agent/cmd/nassimhub-agent/main.go: provisioning = false turns it off).
    A missing provisioning_ap is the built-in default, off."""
    return conf_value(text, 'provisioning_ap') == 'auto' and conf_value(text, 'provisioning') in ('true', 'yes', 'on', '1')


def _plain_file(root, relative):
    """True for a regular file reached through no symbolic link."""
    path = root
    for part in relative.split('/'):
        path = os.path.join(path, part)
        if os.path.islink(path):
            return False
    return os.path.isfile(path)


def setup_ap_findings(root, setup_ap):
    conf = os.path.join(root, AGENT_CONF)
    configured = conf_value(_read(conf), 'provisioning_ap') == 'auto' if _plain_file(root, AGENT_CONF) else False
    if not setup_ap:
        # The two files are reported by the polkit and unit checks.
        return ['setup-ap-configured-without-switch: ' + AGENT_CONF] if configured else []
    findings = []
    for relative in SETUP_AP_FILES:
        if not _plain_file(root, relative):
            findings.append('setup-ap-incomplete: missing ' + relative)
    if not _plain_file(root, AGENT_CONF) or not conf_enables_setup_ap(_read(conf)):
        findings.append('setup-ap-incomplete: ' + AGENT_CONF + ' does not enable it')
    if not _plain_file(root, DNSMASQ):
        findings.append('setup-ap-incomplete: no ' + DNSMASQ + ' (Debian package dnsmasq-base)')
    return findings


def findings(root, files, setup_ap):
    """Every image-policy finding for a tree. files is a list, read three times."""
    files = list(files)
    return (polkit_findings(files, setup_ap) + unit_findings(root, setup_ap) + sysctl_findings(files)
            + setup_ap_findings(root, setup_ap))


def enable_setup_ap(text):
    """The default configuration with the access point switched on.

    Only for the copy that goes into a package built with NSH_SETUP_AP=on. Each
    key must be present exactly once: a configuration this function does not
    understand is refused, not appended to.
    """
    for key, value in (('provisioning', 'true'), ('provisioning_ap', 'auto')):
        pattern = re.compile(r'(?m)^[ \t]*%s[ \t]*=.*$' % re.escape(key))
        if len(pattern.findall(text)) != 1:
            raise ValueError(f'the configuration does not have exactly one "{key} =" line')
        text = pattern.sub(f'{key} = {value}', text)
    # The shipped comment says the access point is off; in this copy it is not.
    text = re.sub(r'(?m)^#[^\n]*setup access point is off[^\n]*\n(?=provisioning_ap = auto$)',
                  '# Switched on by scripts/package-factory.sh (NSH_SETUP_AP=on) for hardware acceptance.\n'
                  '# The setup access point is NOT yet verified on hardware; `off` turns it off again.\n', text)
    if not conf_enables_setup_ap(text):
        raise ValueError('the rewritten configuration does not enable the setup access point')
    return text


def required_packages(repository):
    with open(os.path.join(repository, 'firmware/debian-packages.json')) as handle:
        return json.load(handle)['setup_access_point']['packages']


def main(arguments):
    if len(arguments) == 2 and arguments[0] == 'enable-setup-ap':
        with open(arguments[1]) as handle:
            text = handle.read()
        try:
            text = enable_setup_ap(text)
        except ValueError as error:
            print(f'enable-setup-ap: {error}', file=sys.stderr)
            return 1
        with open(arguments[1], 'w') as handle:
            handle.write(text)
        return 0
    if len(arguments) == 2 and arguments[0] == 'require-dnsmasq':
        if _plain_file(os.path.abspath(arguments[1]), DNSMASQ):
            return 0
        print(f'NSH_SETUP_AP=on needs /{DNSMASQ} in the input rootfs: install the Debian package dnsmasq-base '
              '(NetworkManager starts it to give the phone an address).', file=sys.stderr)
        return 1
    if arguments == ['actions']:
        for title, table in (('always', BASE_POLKIT), ('only with NSH_SETUP_AP=on', SETUP_AP_POLKIT)):
            for relative, actions in table.items():
                for action, why in actions.items():
                    print(f'{title}\t{relative}\t{action}\t{why}')
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
