#!/usr/bin/env python3
"""The public release-key statement (`release-keys.json`). Standard library only.

    release_keys.py statement --keyring ota-keys.json --out DIR [--previous release-keys.json]
                              [--supersedes NEW_ID=OLD_ID ...] [--note KEY_ID=TEXT ...]
                              [--retired KEY_ID=REASON ...] [--issued YYYY-MM-DD]
    release_keys.py check --statement release-keys.json [--sha256 HEX] --keyring ota-keys.json

statement
    Describes the PUBLIC keys of a release keyring (`nsh-release keyring`) so
    that anyone can compare the key file inside an image, or the one a NAS was
    given, with what the project published: key ids, algorithms, public keys,
    a SHA-256 fingerprint of each key, the SHA-256 of the key file itself,
    free-text validity notes and which key supersedes which.

    THE STATEMENT IS NOT SIGNED. `nsh-release sign` signs agent update
    manifests only (it decodes its input as one and refuses unknown fields),
    and no signature format is invented here. The statement's authenticity is
    that of the channel it is published on - a signed git tag, the release
    page - together with its SHA-256 (`release-keys.json.sha256`), which should
    be repeated in the release announcement. A statement fetched from anywhere
    else proves nothing.

    Nothing in a device reads this file. It does not add, expire or revoke a
    key: a device trusts exactly the keys in /etc/nassimhub/ota-keys.json. A
    `retired` entry is information for people, not a revocation.

check
    Compares a key file (taken out of an image or off a NAS) with a statement:
    every key in the file must be an active key of the statement with the same
    public key. Keys the statement lists that the file lacks are reported, not
    failed (an image made before a rotation). --sha256 pins the statement to
    the hash from the release announcement.

A private key file is refused as a keyring (scripts/genericrules.py), and only
the reason is printed, never the content.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import genericrules as rules  # noqa: E402

KIND = 'nassimhub-release-key-statement'
NAME = 'release-keys.json'
KEY_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
UNSIGNED = ('This statement is NOT signed. Its authenticity is that of the channel it was published on (a signed git tag, '
            'the release page) and of its SHA-256 as repeated in the release announcement. It does not add, expire or '
            'revoke any key on a device: a device trusts exactly the keys in /etc/nassimhub/ota-keys.json.')


class StatementError(Exception):
    """A reason no statement is written, or a check fails; for the operator."""


def read_keyring(path):
    raw = pathlib.Path(path).read_bytes()
    problem = rules.public_keyring_problem(raw)
    if problem:
        # The reason, never the content: this may be a private key file.
        raise StatementError(f'{os.path.basename(str(path))} is not a PUBLIC release keyring ({problem})')
    return raw, json.loads(raw)


def fingerprint(encoded):
    return hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest()


def keyring_keys(document):
    """The keys of a keyring as statement entries, sorted by (key id, algorithm)."""
    keys = [{'key_id': key_id, 'algorithm': 'ed25519', 'public_key': encoded, 'sha256': fingerprint(encoded)}
            for key_id, encoded in document['ed25519'].items()]
    keys += [{'key_id': key_id, 'algorithm': identity['algorithm'], 'public_key': identity['public_key'],
              'sha256': fingerprint(identity['public_key'])}
             for key_id, identity in document.get('ml_dsa', {}).items()]
    return sorted(keys, key=lambda key: (key['key_id'], key['algorithm']))


def pairs(values, what):
    result = {}
    for value in values or []:
        name, separator, text = value.partition('=')
        if not separator or not KEY_ID.match(name) or not text.strip():
            raise StatementError(f'{what} must be KEY_ID=VALUE, not {value!r}')
        if name in result:
            raise StatementError(f'{what} names {name} twice')
        result[name] = text.strip()
    return result


def load_statement(path, sha256=None):
    raw = pathlib.Path(path).read_bytes()
    if sha256 is not None and hashlib.sha256(raw).hexdigest() != sha256.strip().lower():
        raise StatementError(f'{os.path.basename(str(path))} does not have the expected SHA-256; it is not the published statement')
    try:
        statement = json.loads(raw)
    except ValueError:
        raise StatementError('the statement is not JSON')
    if not isinstance(statement, dict) or statement.get('kind') != KIND or statement.get('schema') != 1:
        raise StatementError('not a release-key statement (kind/schema)')
    for group in ('keys', 'retired'):
        if not isinstance(statement.get(group), list):
            raise StatementError(f'the statement has no {group} list')
        for key in statement[group]:
            if (not isinstance(key, dict) or not KEY_ID.match(str(key.get('key_id', '')))
                    or not isinstance(key.get('public_key'), str) or key.get('sha256') != fingerprint(key['public_key'])):
                raise StatementError('the statement has an entry whose fingerprint does not match its public key')
    return statement


def build(keyring_raw, keyring, supersedes=None, notes=None, retired=None, previous=None, issued=None):
    """The statement for a keyring. `previous` (an earlier statement) supplies the keys that are no longer in it."""
    supersedes, notes, retired = supersedes or {}, notes or {}, retired or {}
    keys = keyring_keys(keyring)
    active = {key['key_id'] for key in keys}
    earlier = {}
    if previous:
        for key in previous['keys'] + previous['retired']:
            earlier.setdefault((key['key_id'], key['algorithm']), key)
        for key in keys:
            old = earlier.get((key['key_id'], key['algorithm']))
            if old and old['public_key'] != key['public_key']:
                # A key id names one key for ever; a changed key under an old id
                # is exactly what a reader of this statement must never accept.
                raise StatementError(f"key id {key['key_id']} ({key['algorithm']}) has a different public key than in the previous statement; "
                                     'a new key needs a new key id')
    gone = sorted({key_id for key_id, _ in earlier} - active)
    for name in list(supersedes) + list(notes):
        if name not in active:
            raise StatementError(f'{name} is not a key id of this keyring')
    for new, old in supersedes.items():
        if old == new or (old not in active and old not in gone):
            raise StatementError(f'--supersedes {new}={old}: {old} is neither in this keyring nor in the previous statement')
    for name in retired:
        if name in active:
            raise StatementError(f'{name} is still in the keyring: a key is retired by removing it from the key file, then stating why')
        if name not in gone:
            raise StatementError(f'--retired {name}: not a key of the previous statement')
    for key in keys:
        key['status'] = 'active'
        key['supersedes'] = supersedes.get(key['key_id'])
        key['validity_note'] = notes.get(key['key_id'], '')
    retired_entries = []
    for (key_id, _algorithm), key in sorted(earlier.items()):
        if key_id in active:
            continue
        retired_entries.append({'key_id': key_id, 'algorithm': key['algorithm'], 'public_key': key['public_key'], 'sha256': key['sha256'],
                                'status': 'retired',
                                'reason': retired.get(key_id) or key.get('reason') or 'removed from the release keyring (no reason stated)'})
    return {
        'schema': 1, 'kind': KIND, 'issued': issued,
        'signed': False, 'authenticity': UNSIGNED,
        'keyring': {'file': '/etc/nassimhub/ota-keys.json', 'sha256': hashlib.sha256(keyring_raw).hexdigest(),
                    'note': 'SHA-256 of the key file exactly as `nsh-release keyring` wrote it and as it is installed in an image; '
                            'compare with `sha256sum /etc/nassimhub/ota-keys.json`. An image made before or after a rotation has '
                            'another file: compare key by key with `publish-keys.sh --check`.'},
        'keys': keys,
        'retired': retired_entries,
        'retired_note': 'Retired keys are listed so that a key file still carrying one can be recognised. Listing a key here does NOT '
                        'revoke it on any device; only an image whose key file lacks the key does (docs/KEY-MANAGEMENT.md).',
    }


def check(statement, keyring_raw, keyring):
    """(problems, notes) of a key file against a statement."""
    active = {(key['key_id'], key['algorithm']): key for key in statement['keys']}
    retired = {(key['key_id'], key['algorithm']): key for key in statement['retired']}
    problems, notes, seen = [], [], set()
    for key in keyring_keys(keyring):
        identity = (key['key_id'], key['algorithm'])
        seen.add(identity)
        if identity in active:
            if active[identity]['public_key'] != key['public_key']:
                problems.append(f"{key['key_id']} ({key['algorithm']}): the public key differs from the published one")
        elif identity in retired and retired[identity]['public_key'] == key['public_key']:
            problems.append(f"{key['key_id']} ({key['algorithm']}): RETIRED in the statement ({retired[identity]['reason']}) "
                            'but still trusted by this key file')
        else:
            problems.append(f"{key['key_id']} ({key['algorithm']}): not a key the statement lists")
    for identity in sorted(set(active) - seen):
        notes.append(f'{identity[0]} ({identity[1]}): published, not in this key file (an image from before a rotation?)')
    if hashlib.sha256(keyring_raw).hexdigest() == statement.get('keyring', {}).get('sha256'):
        notes.append('the key file is byte for byte the published one')
    return problems, notes


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('statement')
    make.add_argument('--keyring', required=True)
    make.add_argument('--out', required=True)
    make.add_argument('--previous')
    make.add_argument('--supersedes', action='append')
    make.add_argument('--note', action='append')
    make.add_argument('--retired', action='append')
    make.add_argument('--issued')
    verify = commands.add_parser('check')
    verify.add_argument('--statement', required=True)
    verify.add_argument('--sha256')
    verify.add_argument('--keyring', required=True)
    arguments = parser.parse_args(argv)
    try:
        raw, keyring = read_keyring(arguments.keyring)
        if arguments.command == 'check':
            statement = load_statement(arguments.statement, arguments.sha256)
            problems, notes = check(statement, raw, keyring)
            for note in notes:
                print('note: ' + note)
            if problems:
                print('Release key check FAILED:')
                for problem in problems:
                    print('  ' + problem)
                return 1
            print('Release key check PASS: every key in the key file is an active key of the statement'
                  + ('' if arguments.sha256 else ' (the statement itself was NOT pinned with --sha256: it is only as good as where it came from)'))
            return 0
        issued = arguments.issued
        if not issued:
            epoch = os.environ.get('SOURCE_DATE_EPOCH')
            moment = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch
                      else datetime.datetime.now(datetime.timezone.utc))
            issued = moment.strftime('%Y-%m-%d')
        elif not re.match(r'^\d{4}-\d{2}-\d{2}$', issued):
            raise StatementError('--issued must be YYYY-MM-DD')
        previous = load_statement(arguments.previous) if arguments.previous else None
        statement = build(raw, keyring, pairs(arguments.supersedes, '--supersedes'), pairs(arguments.note, '--note'),
                          pairs(arguments.retired, '--retired'), previous, issued)
        out = pathlib.Path(arguments.out)
        out.mkdir(parents=True, exist_ok=True)
        text = json.dumps(statement, indent=2, ensure_ascii=False) + '\n'
        # The published file must itself be free of anything private.
        if rules.scan_bytes(text.encode()):
            raise StatementError('the statement would contain private key material; nothing was written')
        (out / NAME).write_text(text, encoding='utf-8')
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        (out / (NAME + '.sha256')).write_text(f'{digest}  {NAME}\n')
        print(f"wrote {out / NAME}: {len(statement['keys'])} active key(s), {len(statement['retired'])} retired; UNSIGNED")
        print(f'sha256 {digest}  (repeat this value in the release announcement / signed tag message)')
        return 0
    except (StatementError, OSError, ValueError) as error:
        print(f'release_keys: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
