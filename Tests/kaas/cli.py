#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import os.path
import sys

import click

from k8s_test import run_testcases, Config
from plugin.run_plugin import init_plugin
# this is a little hack-y: import scs_cert_lib from parent directory
# TODO turn scs_cert_lib into a pip-package, then require it
# (no need to put it in PyPI, though; it can be installed from within this repo)
sys.path.insert(0, os.path.abspath('..'))
from scs_cert_lib import load_spec, compile_testcases, MONITOR_URL, enter_report


BASEDIR = os.path.dirname(__file__)
DEFAULT_SPECPATH = os.path.join(BASEDIR, '..', 'scs-compatible-kaas.yaml')
# sci for scs-compatible-kaas
STATE_PATH = os.path.join(os.path.expanduser('~'), '.local', 'share', 'scs', 'sck')

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
@click.option('--execution-mode', 'mode', type=click.Choice(('serial', 'parallel', 'dry')), default='serial')
@click.argument('subject', type=str)
def run(subject, specpath, version, sections, tests, monitor_url, mode):
    title, all_testcase_ids = compile_testcases(
        load_spec(specpath),
        version=version, sections=sections, tests=tests,
    )
    logger.info(f"{title}: {len(all_testcase_ids)} testcases")
    config = Config(subject)
    config.statedir = STATE_PATH
    config.testcases = all_testcase_ids
    config.mode = mode
    config.setup()
    report = run_testcases(config)
    enter_report(STATE_PATH, report, monitor_url)


@cli.command()
@click.argument('subject', type=str)
def provision(subject):
    """
    create k8s clusters
    """
    init_plugin(subject, statedir=STATE_PATH).create_cluster()


@cli.command()
@click.argument('subject', type=str)
def unprovision(subject):
    """
    clean up k8s clusters
    """
    init_plugin(subject, statedir=STATE_PATH).delete_cluster()


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    cli()
