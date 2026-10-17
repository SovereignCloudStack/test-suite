#!/usr/bin/env python3
# vim: set ts=4 sw=4 et:

"""Kubernetes testcase runner

(c) Matthias Büchse <matthias.buechse@alasca.cloud>, 7/2026
SPDX-License-Identifier: CC-BY-SA 4.0
"""

import logging
import os
import os.path
import sys
import uuid

import click

from scs_0210_version_policy.k8s_version_policy import version_policy_check
from sonobuoy_handler.sonobuoy_handler import SonobuoyHandler
from plugin.run_plugin import init_plugin

# this is a little hack-y: import scs_cert_lib from parent directory
# TODO turn scs_cert_lib into a pip-package, then require it
# (no need to put it in PyPI, though; it can be installed from within this repo)
sys.path.insert(0, os.path.abspath('..'))
from scs_cert_lib import load_spec, compile_testcases, MONITOR_URL, enter_report, \
    load_env_yaml_section, attest, LogHandler, select_versions, augment_scores, \
    Aggregator


BASEDIR = os.path.dirname(__file__)
DEFAULT_SPECPATH = os.path.join(BASEDIR, '..', 'scs-compatible-kaas.yaml')
# sci for scs-compatible-kaas
STATE_PATH = os.path.join(os.path.expanduser('~'), '.local', 'share', 'scs', 'sck')

PREFLIGHT_PSEUDO = "scs-0502-preflight"  # pseudo testcase to record preflight check abort
TESTCASES = {
    'cncf-k8s-conformance': lambda config, name: run_sono(config, name, '--mode=certified-conformance'),
    'kaas-networking-check': lambda config, name: run_sono(config, name, '--e2e-focus "NetworkPolicy"'),
    'version-policy-check': lambda config, _: version_policy_check(config.kubeconfig_path),
}

SCS_SONOBUOY_CONFIG_PATH = os.path.join(BASEDIR, 'scs-sonobuoy-config-v1.yaml')

logger = logging.getLogger(__name__)


def usage(rcode=1, file=sys.stderr):
    """help output"""
    print("""
Usage: k8s_test.py [options] testcase-id1 ... testcase-idN
Options:
  [-k/--kubeconfig KUBECONFIG_PATH] (optional)
  [-s/--subject SUBJECT] (required)
  [--execution-mode MODE] Sonobuoy mode: serial, parallel, or dry
Runs specified testcases against the default context in kubeconfig provided
via -k (falling back to SUBJECT/kubeconfig.yaml if not explicitly provided).
Reports inconsistencies, errors etc.; returns 0 on success.
Instead of listing testcase-ids, you can supply a single dash (-)
to have them read from stdin, one testcase-id per line.
""".strip(), file=file)
    sys.exit(rcode)


class Config:
    def __init__(self, subject):
        self.kubeconfig_path = None
        self.statedir = '.'
        self.subject = subject
        self.mode = 'serial'
        self.testcases = []
        self.env = {}

    def setup(self):
        self.env = load_env_yaml_section(self.subject)
        if not self.kubeconfig_path:
            default = os.path.join(self.statedir, self.subject, 'kubeconfig.yaml')
            self.kubeconfig_path = self.env.get('kubeconfig', default)

    def compute_sono_args(self, *args):
        if self.mode == 'parallel':
            # This is merely a shortcut to simplify commandline in scs-compatible-kaas.yaml
            # For more on parallel execution, see https://github.com/vmware-tanzu/sonobuoy/issues/1435
            args += ('--e2e-parallel=true', )
        elif self.mode == 'dry':
            # mutually exclusive with parallel, it turns out!
            args += ('--plugin-env e2e.E2E_DRYRUN=true', )
        return args + ('--plugin-env e2e.E2E_EXTRA_ARGS=--ginkgo.flake-attempts=2', )


def run_sono(config, testcase, *args):
    return_code = SonobuoyHandler(
        SCS_SONOBUOY_CONFIG_PATH, testcase, config.kubeconfig_path,
        result_dir_name=os.path.join(os.path.dirname(config.kubeconfig_path), testcase),
        args=config.compute_sono_args(*args),
        sonobuoy_fix=config.env.get('sonobuoy_fix', 'none'),
    ).run()
    return return_code == 0


def run_preflight_checks(config):
    # ideally, make sure that we can connect to the cloud
    # here, at least check that the file exists
    if not os.path.isfile(config.kubeconfig_path):
        logger.critical(f"pre-flight check failed: file {config.kubeconfig_path!r} does not exist")
        del config.testcases[:]
        return False
    invalid = []
    for testcase in config.testcases:
        if testcase not in TESTCASES:
            invalid.append(testcase)
    if invalid:
        logger.critical(f"Invalid/unkown testcases detected: {invalid}")
        config.testcases[:] = [tc for tc in config.testcases if tc not in invalid]
        return False
    return True


def run_testcases(config):
    log = []
    logging.root.addHandler(LogHandler(level=logging.DEBUG, log=log))

    attestations = [
        attest(config.subject, PREFLIGHT_PSEUDO, lambda: run_preflight_checks(config)),
    ] + [
        attest(config.subject, testcase, lambda: TESTCASES[testcase](config, testcase))
        for testcase in config.testcases
    ]

    return {
        'uuid': str(uuid.uuid4()),
        'creator': 'k8_test.py v0.1.0',
        'attestations': attestations,
        'log': log,
        'attachments': {},
    }


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
@click.option('--version', '-V', 'version', type=str, default=None)
@click.option('--specpath', 'specpath', type=str, default=DEFAULT_SPECPATH)
@click.option('--monitor-url', 'monitor_url', type=str, default=MONITOR_URL)
@click.argument('subjects', required=True, nargs=-1, type=str)
def aggregate(subjects, specpath, version, monitor_url):
    """
    update scores from cm
    """
    spec = load_spec(specpath)
    versions = select_versions(spec, version)
    scores = augment_scores(STATE_PATH, subjects[0], monitor_url)

    a = Aggregator(scores)
    for version in versions:
        if len(subjects) > 1:
            for subject in subjects[1:]:
                # compute {subject}/{version.object}
                a.aggregate_version(subject, version)
            # compute {subject[0]}/{version.object}
            a.aggregate_subjects(version['object']['id'], subjects)
        else:
            a.aggregate_version(subjects[0], version)

    enter_report(STATE_PATH, a.make_report(), monitor_url)


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
