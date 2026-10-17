#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import os.path
import sys

import click

from openstack_test import run_testcases, openstack
# this is a little hack-y: import scs_cert_lib from parent directory
# TODO turn scs_cert_lib into a pip-package, then require it
# (no need to put it in PyPI, though; it can be installed from within this repo)
sys.path.insert(0, os.path.abspath('..'))
from scs_cert_lib import load_spec, compile_testcases, MONITOR_URL, enter_report


BASEDIR = os.path.dirname(__file__)
DEFAULT_SPECPATH = os.path.join(BASEDIR, '..', 'scs-compatible-iaas.yaml')
# sci for scs-compatible-iaas
STATE_PATH = os.path.join(os.path.expanduser('~'), '.local', 'share', 'scs', 'sci')

logger = logging.getLogger(__name__)


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
    title, all_testcase_ids = compile_testcases(
        load_spec(specpath),
        version=version, sections=sections, tests=tests,
    )
    logger.info(f"{title}: {len(all_testcase_ids)} testcases")
    report = run_testcases(subject, all_testcase_ids)
    enter_report(STATE_PATH, report, monitor_url)


@cli.command()
@click.argument('subject', type=str)
def cleanup(subject):
    """
    clean up any lingering IaaS resources
    """
    run_testcases(subject, ('cleanup', ))


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    openstack.enable_logging(debug=False)
    cli()
