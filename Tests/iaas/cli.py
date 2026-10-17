#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import os.path
import sys

import click
import yaml

from openstack_test import run_testcases
# this is a little hack-y: import scs_cert_lib from parent directory
# TODO turn scs_cert_lib into a pip-package, then require it
# (no need to put it in PyPI, though; it can be installed from within this repo)
sys.path.insert(0, os.path.abspath('..'))
from scs_cert_lib import load_spec, compile_testcases, MONITOR_URL, \
    sign_report, upload_report, write_yaml


BASEDIR = os.path.dirname(__file__)
DEFAULT_SPECPATH = os.path.join(BASEDIR, '..', 'scs-compatible-iaas.yaml')
# sci for scs-compatible-iaas
STATE_PATH = os.path.join(os.path.expanduser('~'), '.local', 'share', 'scs', 'sci')
SCORE_PATH = os.path.join(STATE_PATH, 'scorecard.yaml')

logger = logging.getLogger(__name__)


def _load_yaml(path, default=None):
    if not os.path.exists(path):
        if default is None:
            raise FileNotFoundError(path)
        return default
    with open(path, "r", encoding="UTF-8") as fileobj:
        return yaml.load(fileobj, Loader=yaml.SafeLoader)


def _load_spec(specpath=DEFAULT_SPECPATH):
    return load_spec(_load_yaml(specpath))


def _load_scores(scorepath=SCORE_PATH):
    return _load_yaml(scorepath, default={})


@click.group()
def cli():
    return


@cli.command()
@click.option('--version', '-V', 'version', type=str, default=None)
@click.option('--tests', '-t', 'tests', type=str, default=None)
@click.option('--section', '-S', 'sections', type=str, multiple=True)
@click.option('--specpath', 'specpath', type=str, default=DEFAULT_SPECPATH)
@click.option('--monitor-url', 'monitor_url', type=str, default=MONITOR_URL)
@click.argument('subject', type=str)
def run(subject, specpath, version, sections, tests, monitor_url):
    spec = _load_spec(specpath)
    title, all_testcase_ids = compile_testcases(
        spec, version=version, sections=sections, tests=tests,
    )
    logger.info(f"{title}: {len(all_testcase_ids)} testcases")
    report = run_testcases(subject, all_testcase_ids)
    uuid = report['uuid']
    basepath = STATE_PATH
    os.makedirs(basepath, exist_ok=True)
    # save report
    report_yaml = os.path.join(basepath, f'report-{uuid}.yaml')
    if os.path.exists(report_yaml):
        raise RuntimeError(f"File 'report-{uuid}.yaml' already exists; report uuid NOT UNIQUE?")
    write_yaml(report_yaml, report)
    sign_report(report_yaml)
    upload_report(report_yaml, monitor_url)
    # update local scores
    scorecard = _load_scores()
    _update_scorecard(scorecard, report, spec['testcases'])
    write_yaml(SCORE_PATH, scorecard)
    # prune local reports
    _prune_reports(scorecard)


def _update_scorecard(scorecard, report, testcase_lookup):
    uuid = report['uuid']
    for attestation in report['attestations']:
        subject, object_ = attestation['subject'], attestation['object']
        contender = scorecard.setdefault(subject, {}).setdefault(object_, {})
        if not contender or contender['timestamp'] < attestation['timestamp']:
            contender.update(**attestation, report=uuid)


def _prune_reports(scorecard, statepath=STATE_PATH):
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


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
    cli()
