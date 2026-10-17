#!/usr/bin/env python3
# vim: set ts=4 sw=4 et:
#
# scs_cert_lib.py
#
# (c) Matthias Büchse <matthias.buechse@cloudandheat.com>
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from datetime import datetime, date, timedelta
import logging
import os.path
import re
import shutil
import subprocess
import tempfile

import yaml


logger = logging.getLogger(__name__)
MONITOR_URL = "http://localhost"  # "https://compliance.sovereignit.cloud/"
CONFIG_PATH = os.path.join(os.path.expanduser('~'), '.config', 'scs')
KEYFILE_PATH = os.path.join(CONFIG_PATH, '.secret', 'keyfile')
TOKENFILE_PATH = os.path.join(CONFIG_PATH, '.secret', 'tokenfile')

# valid keywords for various parts of the spec, to be checked using `check_keywords`
KEYWORDS = {
    'spec': ('uuid', 'name', 'url', 'versions', 'testcases', 'timeline'),
    'versions': ('version', 'object', 'stabilized_at'),
    'testcases': ('section', 'id', 'description', 'url', 'components'),
    'include': ('ref', 'lifetime'),
}


def _check_keywords(ctx, d, keywords=KEYWORDS):
    """
    Recursively check `d` (usually a `dict`, but maybe a `list` or a `tuple`) for correctness.

    Returns number of errors.

    Here, correctness means that the dict may only use keywords as given via `keywords`.
    """
    valid = keywords.get(ctx)
    if valid is None:
        return 0  # stop recursion
    if isinstance(d, (list, tuple)):
        return sum(_check_keywords(ctx, v, keywords=keywords) for v in d)
    if not isinstance(d, dict):
        return 0
    invalid = [k for k in d if k not in valid]
    if invalid:
        logger.error(f"{ctx} uses unknown keywords: {','.join(invalid)}")
    return len(invalid) + sum(_check_keywords(k, v, keywords=keywords) for k, v in d.items())


def _collect_atomic_testcases(object_, result_list):
    components = object_.get('components')
    if components is None:
        result_list.append(object_)
        return
    for child in components:
        _collect_atomic_testcases(child['ref'], result_list)


def collect_atomic_testcases(*objects):
    result_list = []
    for object_ in objects:
        _collect_atomic_testcases(object_, result_list)
    return result_list


def _resolve_spec(spec: dict):
    """rewire `spec` so as to make most lookups via name unnecessary, and to find name errors early"""
    if isinstance(spec['versions'], dict):
        raise RuntimeError('spec dict already in resolved form')
    # there are currently two types of objects that are being referenced by name or id
    # - modules, referenced by id
    # - versions, referenced by name (unfortunately, the field is called "version")
    # step 1. build lookups
    testcase_lookup = {}
    testcases = spec.get('testcases', ())
    for testcase in testcases:
        id_ = testcase['id']
        if id_ in testcase_lookup:
            raise RuntimeError(f"duplicate testcase {id_}")
        testcase['attn'] = 0  # count: how many stable versions list this in target 'main'?
        testcase_lookup[id_] = testcase
    version_lookup = {version['version']: version for version in spec['versions']}
    # step 2. check for duplicates:
    if len(version_lookup) != len(spec['versions']):
        raise RuntimeError("spec contains duplicate version ids")
    # step 3. replace fields 'modules' and 'versions' by respective lookups
    spec['versions'] = version_lookup
    # step 3a. add testcase lookup
    spec['testcases'] = testcase_lookup
    # step 4. resolve references
    # step 4a. resolve references to testcases in components
    # in this step, we also normalize the include form
    for testcase in testcases:
        components = testcase.get('components')
        if not components:
            continue
        testcase['components'] = [
            {'ref': testcase_lookup[inc], 'lifetime': None} if isinstance(inc, str) else
            {**inc, 'ref': testcase_lookup[inc['ref']]}
            for inc in components
        ]
    # step 4b. resolve 'object' in versions, collect all atomic testcases
    for idx, version in enumerate(spec['versions'].values()):
        version['_idx'] = idx
        object_ = testcase_lookup[version['object']]
        testcases = collect_atomic_testcases(object_)
        attn = 0 if 'stabilized_at' not in version else 1
        for testcase in testcases:
            testcase['attn'] += attn
        version['object'] = object_
        version['testcase_ids'] = [testcase['id'] for testcase in testcases]
    # step 4c. resolve references to versions in timeline
    # on second thought, let's not go there: it's a canonical extension map, and it should remain that way.
    # however, we still have to look for name errors
    for entry in spec['timeline']:
        for vname in entry['versions']:
            # trigger KeyError
            _ = version_lookup[vname]


def load_spec(document: dict) -> dict:
    """check `document` (usually parsed YAML) and convert for further usage"""
    if isinstance(document, str):
        document = load_yaml(document)
    if _check_keywords('spec', document):
        # super simple syntax check (recursive)
        raise RuntimeError('syntax problems in spec file. bailing')
    _resolve_spec(document)
    return document


def annotate_validity(timeline: list, versions: dict, checkdate: date):
    """annotate `versions` with validity info from `timeline` (note that this depends on `checkdate`)"""
    validity_lookup = max(
        (entry for entry in timeline if entry['date'] <= checkdate),
        key=lambda entry: entry['date'],
        default={},
    ).get('versions', {})
    for vname, version in versions.items():
        validity = validity_lookup.get(vname)
        version['validity'] = validity or 'deprecated'
        version['_explicit_validity'] = validity


def add_period(dt: datetime, period: str) -> datetime:
    """
    Given a `datetime` instance `dt` and a `str` instance `period`, compute the `datetime` when this period
    expires, where period is one of: "day", "week", "month", or "quarter". For instance, with a period
    of (calendar) "week", this period expires on midnight the next monday after `dt` + 7 days. This
    computation is used to implement Regulations 2 and 3 of the standard scs-0004 -- see

    https://docs.scs.community/standards/scs-0004-v1-achieving-certification#regulations
    """
    # compute the moment of expiry (so we are valid before that point, but not on that point)
    if period == 'day':
        dt += timedelta(days=2)
        return datetime(dt.year, dt.month, dt.day)  # omit time so as to arrive at midnight
    # week is default, so use it if period is None
    if period is None or period == 'week':
        dt += timedelta(days=14 - dt.weekday())
        return datetime(dt.year, dt.month, dt.day)  # omit time so as to arrive at midnight
    if period == 'month':
        if dt.month == 11:
            return datetime(dt.year + 1, 1, 1)
        if dt.month == 12:
            return datetime(dt.year + 1, 2, 1)
        return datetime(dt.year, dt.month + 2, 1)
    if period == 'quarter':
        if dt.month >= 10:
            return datetime(dt.year + 1, 4, 1)
        if dt.month >= 7:
            return datetime(dt.year + 1, 1, 1)
        if dt.month >= 4:
            return datetime(dt.year, 10, 1)
        return datetime(dt.year, 7, 1)
    if period == 'year':
        if dt.month == 11:
            return datetime(dt.year + 2, 1, 1)
        if dt.month == 12:
            return datetime(dt.year + 2, 2, 1)
        return datetime(dt.year + 1, dt.month + 2, 1)
    raise RuntimeError(f'unknown period: {period}')


def eval_buckets(results, testcase_ids) -> dict:
    """
    returns buckets of test cases by means of a mapping
    """
    by_value = defaultdict(list)
    for testcase_id in testcase_ids:
        value = results.get(testcase_id, {})
        if isinstance(value, dict):
            value = value.get('result')
        by_value[value].append(testcase_id)
    return by_value


def evaluate(results, testcase_ids) -> int:
    """returns overall result"""
    buckets = eval_buckets(results, testcase_ids)
    for value in ('fail', None, 'dnf'):
        if buckets[value]:
            return value
    return 'pass'


def select_valid(versions: list) -> list:
    return [version for version in versions if version['_explicit_validity']]


def compile_testcases(spec, version=None, tests=None, sections=None, checkdate=None):
    if checkdate is None:
        checkdate = date.today()
    annotate_validity(spec['timeline'], spec['versions'], checkdate)
    if version is None:
        versions = select_valid(spec['versions'].values())
    else:
        versions = [spec['versions'].get(version)]
        if versions[0] is None:
            raise RuntimeError(f"Requested version '{version}' not found")
    if not versions:
        raise RuntimeError(f"No valid version found for {checkdate}")
    title = spec['name']
    if sections:
        title += f" [sections: {', '.join(sections)}]"
    if tests:
        title += f" [tests: '{tests}']"
        tests_re = re.compile(tests)
    # collect all testcases we need
    testcase_lookup = spec['testcases']
    all_testcase_ids = set()
    for version in versions:
        for tc_id in version['testcase_ids']:
            if sections and testcase_lookup.get(tc_id, {}).get('section') not in sections:
                continue
            if tests and not tests_re.match(tc_id):
                continue
            all_testcase_ids.add(tc_id)
    return title, sorted(all_testcase_ids)


def sign_report(target_path):
    return subprocess.run([
        shutil.which('ssh-keygen'),
        '-Y', 'sign',
        '-f', KEYFILE_PATH,
        '-n', 'report',
        target_path,
    ]).returncode


def upload_report(target_path, monitor_url=MONITOR_URL):
    try:
        with open(TOKENFILE_PATH, "r") as fileobj:
            auth_token = fileobj.read().strip()
    except Exception as e:
        logger.error(f"Unable to load token ({e!s}). Aborting upload to compliance monitor")
        return 1
    return subprocess.run([
        shutil.which('curl'),
        '--fail-with-body',
        '--data-binary', f'@{target_path}.sig',
        '--data-binary', f'@{target_path}',
        '-H', 'Content-Type: application/x-signed-yaml',
        '-H', f'Authorization: Basic {auth_token}',
        f"{monitor_url.removesuffix('/')}/reports",
    ]).returncode


def dump_yaml(o):
    return yaml.safe_dump(o, default_flow_style=False, sort_keys=False, explicit_start=True)


def _atomic_write(path, text):
    with tempfile.NamedTemporaryFile(
        mode='w', encoding='UTF-8',
        dir=os.path.dirname(path) or '.',
        delete=False, delete_on_close=False,
    ) as fileobj:
        fileobj.write(text)
    os.rename(fileobj.name, path)


def load_yaml(path, default=None):
    if not os.path.exists(path):
        if default is None:
            raise FileNotFoundError(path)
        return default
    with open(path, "r", encoding="UTF-8") as fileobj:
        return yaml.load(fileobj, Loader=yaml.SafeLoader)


def write_yaml(path, o):
    _atomic_write(path, dump_yaml(o))


def enter_report(statepath, report, monitor_url=MONITOR_URL):
    os.makedirs(statepath, exist_ok=True)
    # save report
    uuid = report['uuid']
    report_yaml = os.path.join(statepath, f'report-{uuid}.yaml')
    if os.path.exists(report_yaml):
        raise RuntimeError(f"File 'report-{uuid}.yaml' already exists; report uuid NOT UNIQUE?")
    write_yaml(report_yaml, report)
    sign_report(report_yaml)
    upload_report(report_yaml, monitor_url)
    # update local scores
    scorepath = os.path.join(statepath, 'scorecard.yaml')
    scorecard = load_scores(scorepath)
    update_scorecard(scorecard, report)
    write_yaml(scorepath, scorecard)
    # prune local reports
    prune_reports(statepath, scorecard)


def load_scores(scorepath):
    return load_yaml(scorepath, default={})


def update_scorecard(scorecard, report):
    uuid = report['uuid']
    for attestation in report['attestations']:
        subject, object_ = attestation['subject'], attestation['object']
        contender = scorecard.setdefault(subject, {}).setdefault(object_, {})
        if not contender or contender['timestamp'] < attestation['timestamp']:
            contender.update(**attestation, report=uuid)


def prune_reports(statepath, scorecard):
    # prune reports that don't occur in scorecard (i.e., old ones)
    report_uuids = set(
        att['report']
        for subj_atts in scorecard.values()
        for att in subj_atts.values()
    )
    fns = os.listdir(statepath)
    for fn in fns:
        if not fn.startswith('report-'):
            continue
        uuid = fn.removeprefix('report-').removesuffix('.sig').removesuffix('.yaml')
        if len(uuid) != 36 or uuid in report_uuids:
            continue
        logger.info(f"Pruning {fn!s}")
        os.unlink(os.path.join(statepath, fn))
