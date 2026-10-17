#!/usr/bin/env python3
# vim: set ts=4 sw=4 et:

"""Kubernetes testcase runner

(c) Matthias Büchse <matthias.buechse@alasca.cloud>, 7/2026
SPDX-License-Identifier: CC-BY-SA 4.0
"""

from datetime import datetime
import getopt
import logging
import os
import os.path
import sys
import uuid

import yaml

from scs_0210_version_policy.k8s_version_policy import version_policy_check
from sonobuoy_handler.sonobuoy_handler import SonobuoyHandler


PREFLIGHT_PSEUDO = "scs-0502-preflight"  # pseudo testcase to record preflight check abort
TESTCASES = {
    'cncf-k8s-conformance': lambda config, name: run_sono(config, name, '--mode=certified-conformance'),
    'kaas-networking-check': lambda config, name: run_sono(config, name, '--e2e-focus "NetworkPolicy"'),
    'version-policy-check': lambda config, _: version_policy_check(config.kubeconfig_path),
}


BASEDIR = os.path.dirname(__file__)
SCS_SONOBUOY_CONFIG_PATH = os.path.join(BASEDIR, 'scs-sonobuoy-config-v1.yaml')

logger = logging.getLogger(__name__)
ENVPATH = os.path.join(os.path.expanduser('~'), '.config', 'scs', 'env.yaml')


def _load_env_yaml_section(path, subject):
    if not os.path.isfile(path):
        return {}
    with open(path, "rb") as fileobj:
        env_yaml = yaml.load(fileobj, Loader=yaml.SafeLoader)
    if not isinstance(env_yaml, dict):
        raise RuntimeError("env.yaml config file available, but not of type dict!")
    result = env_yaml.get(subject, {})
    if not result:
        logger.debug("env.yaml config file available, but no values declared.")
    return result


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

    def apply_argv(self, argv):
        """Parse cli arguments from the script call"""
        try:
            opts, args = getopt.gnu_getopt(argv, "k:s:", ("kubeconfig=", "subject=", "execution-mode="))
        except getopt.GetoptError as exc:
            print(f"CRITICAL: {exc!r}", file=sys.stderr)
            usage(1)
        for opt in opts:
            if opt[0] == "-h" or opt[0] == "--help":
                usage(0)
            elif opt[0] == "-k" or opt[0] == "--kubeconfig":
                self.kubeconfig_path = opt[1]
            elif opt[0] == "-s" or opt[0] == "--subject":
                self.subject = opt[1]
            elif opt[0] == "--execution-mode":
                self.mode = opt[1]
            else:
                usage(2)
        if len(args) == 1 and args[0] == '-':
            args = sys.stdin.read().splitlines()
        self.testcases = [t for t in args if t in TESTCASES]
        if len(self.testcases) != len(args):
            unknown = [a for a in args if a not in self.testcases]
            logger.warning(f"ignoring unknown testcases: {','.join(unknown)}")
        if not self.subject:
            print("CRITICAL: You need to pass -s=SUBJECT.", file=sys.stderr)
            sys.exit(1)
        self.setup()

    def setup(self):
        self.env = _load_env_yaml_section(path=ENVPATH, subject=self.subject)
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


def attest(subject, name, *check_fns):
    """Harness for evaluating testcase `name`.

    Logs beginning and end of computation.
    Calls each fn in `check_fns`.
    Returns attestation dict.
    """
    guid = str(uuid.uuid4())
    timestamp = datetime.now()
    logger.info(f'*** {subject}/{name} ({guid})')
    try:
        result = all(check_fn() for check_fn in check_fns)
    except BaseException:
        logger.debug('exception during check', exc_info=True)
        value = 0
    else:
        value = 1 if result else -1
    result = ['fail', 'dnf', 'pass'][value + 1]
    logger.info(f'+++ {subject}/{name}: {result.upper()}')
    return {
        'guid': guid,
        'timestamp': timestamp,
        'subject': subject,
        'predicate': result,
        'object': name,
    }


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


class _LogHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET, log=None):
        super().__init__(level=level)
        self.log = [] if log is None else log

    def handle(self, record):
        self.log.append(f'{record.levelname}: {record.getMessage()}')


def main(argv):
    # configure logging, disable verbose library logging
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

    config = Config()
    config.apply_argv(argv)

    try:
        run_preflight_checks(config.kubeconfig_path)
    except Exception:
        logger.critical("Pre-flight checks failed. Reporting all testcases as ABORT.")
        for testcase in config.testcases:
            print(f"{testcase}: ABORT")
        raise

    report = run_testcases(config)
    # don't do explicit_start here because that can easily be done by the caller using "echo ---",
    # and then the caller can even add fields such as uuid, subject, and scope
    yaml.safe_dump(report, sys.stdout, default_flow_style=False, sort_keys=False, explicit_start=False)
    return 0


def run_testcases(config):
    log = []
    logging.root.addHandler(_LogHandler(level=logging.DEBUG, log=log))

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


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except BaseException as exc:
        print(f"CRITICAL: {exc!r}", file=sys.stderr)
        sys.exit(1)
