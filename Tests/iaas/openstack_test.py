#!/usr/bin/env python3
# vim: set ts=4 sw=4 et:

"""Openstack testcase runner

(c) Matthias Büchse <matthias.buechse@alasca.cloud>, 8/2025
SPDX-License-Identifier: CC-BY-SA 4.0
"""

import logging
import os.path
import sys
import uuid

import click
import openstack

from cleanup import Janitor
from scs_0100_flavor_naming.flavor_names import compute_flavor_spec
from scs_0100_flavor_naming.flavor_names_check import \
    compute_scs_flavors, compute_scs_0100_syntax_check, compute_scs_0100_semantics_check
from scs_0101_entropy.entropy_check import \
    compute_canonical_image, compute_collected_vm_output, compute_scs_0101_entropy_avail, \
    compute_scs_0101_fips_test
from scs_0102_image_metadata.image_metadata import \
    compute_scs_0102_prop_architecture, compute_scs_0102_prop_hash_algo, compute_scs_0102_prop_min_disk, \
    compute_scs_0102_prop_min_ram, compute_scs_0102_prop_os_version, compute_scs_0102_prop_os_distro, \
    compute_scs_0102_prop_os_purpose, \
    compute_scs_0102_prop_hw_disk_bus, compute_scs_0102_prop_hypervisor_type, compute_scs_0102_prop_hw_rng_model, \
    compute_scs_0102_prop_image_build_date, compute_scs_0102_prop_image_original_user, \
    compute_scs_0102_prop_image_source, compute_scs_0102_prop_image_description, \
    compute_scs_0102_prop_replace_frequency, compute_scs_0102_prop_provided_until, \
    compute_scs_0102_prop_uuid_validity, compute_scs_0102_prop_hotfix_hours, \
    compute_scs_0102_image_recency, compute_scs_0102_os_purpose_uniqueness
from scs_0103_standard_flavors.standard_flavors import \
    SCS_0103_CANONICAL_NAMES, compute_flavor_lookup, compute_scs_0103_flavor
from scs_0104_standard_images.standard_images import \
    SCS_0104_IMAGE_SPECS, compute_scs_0104_source, compute_scs_0104_image, \
    compute_image_lookup_ex, compute_scs_0104_source_ex, compute_scs_0104_source_capi, \
    compute_scs_0104_image_ubuntu_latest
from scs_0114_volume_types.volume_types import \
    compute_volume_type_lookup, compute_scs_0114_syntax_check, compute_scs_0114_aspect_type
from scs_0115_security_groups.security_groups import \
    compute_scs_0115_default_rules
from scs_0116_key_manager.key_manager import \
    ensure_unprivileged, compute_services_lookup, compute_scs_0116_presence, compute_scs_0116_permissions
from scs_0117_volume_backup.volume_backup import \
    compute_scs_0117_test_backup
from scs_0123_mandatory_services.mandatory_services import \
    compute_scs_0123_service_presence, compute_scs_0123_swift_s3

# this is a little hack-y: import scs_cert_lib from parent directory
# TODO turn scs_cert_lib into a pip-package, then require it
# (no need to put it in PyPI, though; it can be installed from within this repo)
sys.path.insert(0, os.path.abspath('..'))
from scs_cert_lib import load_spec, compile_testcases, MONITOR_URL, enter_report, \
    load_env_yaml_section, attest, LogHandler, augment_scores, select_versions, \
    Aggregator, print_prelim_summary, maintain_scorecard, run_multiple_subjects, \
    do_multiple_subjects


BASEDIR = os.path.dirname(__file__)
DEFAULT_SPECPATH = os.path.join(BASEDIR, 'scs-compatible-iaas.yaml')
# sci for scs-compatible-iaas
STATE_PATH = os.path.join(os.path.expanduser('~'), '.local', 'share', 'scs', 'sci')

logger = logging.getLogger(__name__)
PREFLIGHT_PSEUDO = "scs-0501-preflight"  # pseudo testcase to record preflight check abort
FIXED_TESTCASES = (PREFLIGHT_PSEUDO, )
PREFIX = "_scs-"  # used for cleanup: only remove objects whose name starts in PREFIX
IPADDR = "10.1.0."  # used for cleanup: only remove network objects within IPADDR


def usage(rcode=1, file=sys.stderr):
    """help output"""
    print("""
Usage: openstack_test.py [options] testcase-id1 ... testcase-idN
Options:
  [-c/--os-cloud OS_CLOUD] (optional)
  [-s/--subject SUBJECT] (required)
Runs specified testcases against the OpenStack cloud OS_CLOUD
(falling back to SUBJECT if not explicitly provided)
and reports inconsistencies, errors etc. It returns 0 on success.
""".strip(), file=file)
    sys.exit(rcode)


def make_container(subject, cloud=None):
    c = Container()
    c.add_value('subject', subject)
    # env.yaml support
    c.add_function('env', lambda _: load_env_yaml_section(subject=subject))
    c.add_function('cloud', lambda c: c.env.get('cloud', subject) if cloud is None else cloud)
    # Configure an optional list of DNS servers for scs-0101-entropy
    c.add_function('dns_nameservers', lambda c: c.env.get('dns_nameservers'))
    # Configure an optional external network ID for scs-0101-entropy
    c.add_function('external_gateway_net_id', lambda c: c.env.get('external_gateway_net_id'))
    # basic support attributes shared by multiple testcases
    c.add_function('conn', lambda c: openstack.connect(cloud=c.cloud, timeout=32))
    c.add_function('flavors', lambda c: list(c.conn.list_flavors(get_extra=True)))
    c.add_function('images', lambda c: [img for img in c.conn.list_images(show_all=True) if img.visibility in ('public', 'community')])
    c.add_function('image_lookup', lambda c: {img.name: img for img in c.images})
    # scs_0100_flavor_naming
    c.add_function('scs_flavors', lambda c: compute_scs_flavors(c.flavors))
    c.add_function('scs-0100-syntax-check', lambda c: compute_scs_0100_syntax_check(c.scs_flavors))
    c.add_function('scs-0100-semantics-check', lambda c: compute_scs_0100_semantics_check(c.scs_flavors))
    # scs_0101_entropy
    c.add_function('canonical_image', lambda c: compute_canonical_image(c.images))
    c.add_function('collected_vm_output', lambda c: compute_collected_vm_output(
        c.conn, c.flavors, c.canonical_image, c.dns_nameservers, c.external_gateway_net_id,
    ))
    c.add_function('scs-0101-entropy-avail', lambda c: compute_scs_0101_entropy_avail(c.collected_vm_output, c.canonical_image.name))
    c.add_function('scs-0101-fips-test', lambda c: compute_scs_0101_fips_test(c.collected_vm_output, c.canonical_image.name))
    # scs_0102_image_metadata
    c.add_function('scs-0102-prop-architecture', lambda c: compute_scs_0102_prop_architecture(c.images))
    c.add_function('scs-0102-prop-hash_algo', lambda c: compute_scs_0102_prop_hash_algo(c.images))
    c.add_function('scs-0102-prop-min_disk', lambda c: compute_scs_0102_prop_min_disk(c.images))
    c.add_function('scs-0102-prop-min_ram', lambda c: compute_scs_0102_prop_min_ram(c.images))
    c.add_function('scs-0102-prop-os_version', lambda c: compute_scs_0102_prop_os_version(c.images))
    c.add_function('scs-0102-prop-os_distro', lambda c: compute_scs_0102_prop_os_distro(c.images))
    c.add_function('scs-0102-prop-os_purpose', lambda c: compute_scs_0102_prop_os_purpose(c.images))
    c.add_function('scs-0102-prop-hw_disk_bus', lambda c: compute_scs_0102_prop_hw_disk_bus(c.images))
    c.add_function('scs-0102-prop-hypervisor_type', lambda c: compute_scs_0102_prop_hypervisor_type(c.images))
    c.add_function('scs-0102-prop-hw_rng_model', lambda c: compute_scs_0102_prop_hw_rng_model(c.images))
    c.add_function('scs-0102-prop-image_build_date', lambda c: compute_scs_0102_prop_image_build_date(c.images))
    c.add_function('scs-0102-prop-image_original_user', lambda c: compute_scs_0102_prop_image_original_user(c.images))
    c.add_function('scs-0102-prop-image_source', lambda c: compute_scs_0102_prop_image_source(c.images))
    c.add_function('scs-0102-prop-image_description', lambda c: compute_scs_0102_prop_image_description(c.images))
    c.add_function('scs-0102-prop-replace_frequency', lambda c: compute_scs_0102_prop_replace_frequency(c.images))
    c.add_function('scs-0102-prop-provided_until', lambda c: compute_scs_0102_prop_provided_until(c.images))
    c.add_function('scs-0102-prop-uuid_validity', lambda c: compute_scs_0102_prop_uuid_validity(c.images))
    c.add_function('scs-0102-prop-hotfix_hours', lambda c: compute_scs_0102_prop_hotfix_hours(c.images))
    c.add_function('scs-0102-image-recency', lambda c: compute_scs_0102_image_recency(c.images))
    c.add_function('scs-0102-os_purpose-uniqueness', lambda c: compute_scs_0102_os_purpose_uniqueness(c.images))
    # scs_0103_standard_flavors
    c.add_function('flavor_lookup', lambda c: compute_flavor_lookup(c.flavors))
    for canonical_name in SCS_0103_CANONICAL_NAMES:
        nm = canonical_name.removeprefix('SCS-').lower()
        # NOTE we need cn=canonical_name below because anon function only catches a variable's CELL, not its value
        # i.e., if we use canonical_name inside it, we will only get its final value after the loop is done
        c.add_function(
            f'scs-0103-flavor-{nm}',
            lambda c, cn=canonical_name: compute_scs_0103_flavor(c.flavor_lookup, compute_flavor_spec(cn))
        )
    # scs_0104_standard_images
    c.add_function('image_lookup_ex', lambda c: compute_image_lookup_ex(c.images))
    c.add_function('scs-0104-source-capi', lambda c: compute_scs_0104_source_capi(c.image_lookup))
    c.add_function('scs-0104-source-capi-1', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['ubuntu-capi-image-1']))
    c.add_function('scs-0104-source-capi-2', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['ubuntu-capi-image-2']))
    c.add_function('scs-0104-source-ubuntu', lambda c: compute_scs_0104_source_ex(c.image_lookup_ex, 'ubuntu'))
    c.add_function('scs-0104-source-ubuntu-2404', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Ubuntu 24.04']))
    c.add_function('scs-0104-source-ubuntu-2204', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Ubuntu 22.04']))
    c.add_function('scs-0104-source-ubuntu-2004', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Ubuntu 20.04']))
    c.add_function('scs-0104-source-debian', lambda c: compute_scs_0104_source_ex(c.image_lookup_ex, 'debian'))
    c.add_function('scs-0104-source-debian-13', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 13']))
    c.add_function('scs-0104-source-debian-12', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 12']))
    c.add_function('scs-0104-source-debian-11', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 11']))
    c.add_function('scs-0104-source-debian-10', lambda c: compute_scs_0104_source(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 10']))
    c.add_function('scs-0104-image-capi-1', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['ubuntu-capi-image-1']))
    c.add_function('scs-0104-image-capi-2', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['ubuntu-capi-image-2']))
    c.add_function('scs-0104-image-ubuntu-latest', lambda c: compute_scs_0104_image_ubuntu_latest(c.image_lookup_ex))
    c.add_function('scs-0104-image-ubuntu-2404', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Ubuntu 24.04']))
    c.add_function('scs-0104-image-ubuntu-2204', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Ubuntu 22.04']))
    c.add_function('scs-0104-image-ubuntu-2004', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Ubuntu 20.04']))
    c.add_function('scs-0104-image-debian-13', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 13']))
    c.add_function('scs-0104-image-debian-12', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 12']))
    c.add_function('scs-0104-image-debian-11', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 11']))
    c.add_function('scs-0104-image-debian-10', lambda c: compute_scs_0104_image(c.image_lookup, SCS_0104_IMAGE_SPECS['Debian 10']))
    # scs_0114_volume_types
    c.add_function('volume_types', lambda c: c.conn.list_volume_types())
    c.add_function('volume_type_lookup', lambda c: compute_volume_type_lookup(c.volume_types))
    c.add_function('scs-0114-syntax-check', lambda c: compute_scs_0114_syntax_check(c.volume_type_lookup))
    c.add_function('scs-0114-encrypted-type', lambda c: compute_scs_0114_aspect_type(c.volume_type_lookup, 'encrypted'))
    c.add_function('scs-0114-replicated-type', lambda c: compute_scs_0114_aspect_type(c.volume_type_lookup, 'replicated'))
    # scs_0115_security_groups
    c.add_function('scs-0115-default-rules', lambda c: compute_scs_0115_default_rules(c.conn))
    # scs_0116_key_manager
    c.add_function('services_lookup', lambda c: compute_services_lookup(c.conn))
    c.add_function('scs-0116-presence', lambda c: compute_scs_0116_presence(c.services_lookup))
    c.add_function('scs-0116-permissions', lambda c: compute_scs_0116_permissions(c.conn, c.services_lookup))
    # scs_0117_volume_backup
    c.add_function('scs-0117-test-backup', lambda c: compute_scs_0117_test_backup(c.conn))
    # scs_0123_mandatory_services
    for svc in ('compute', 'identity', 'image', 'network', 'load-balancer', 'placement'):
        c.add_function(f'scs-0123-service-{svc}', lambda c: compute_scs_0123_service_presence(c.services_lookup, svc))
    c.add_function('scs-0123-storage-apis', lambda c: compute_scs_0123_service_presence(c.services_lookup, 'volume', 'volumev3', 'block-storage'))
    c.add_function('scs-0123-service-s3', lambda c: compute_scs_0123_service_presence(c.services_lookup, 'object-store-s3'))
    c.add_function('scs-0123-swift-s3', lambda c: compute_scs_0123_swift_s3(c.services_lookup, c.conn))
    # pseudo-testcase: cleanup
    c.add_function('cleanup', lambda c: Janitor(c.conn, PREFIX, IPADDR).cleanup() or True)
    return c


class Container:
    """
    This class does lazy evaluation and memoization. You register any potential value either
    by giving the value directly, using `add_value`, or
    by specifying how it is computed using `add_function`,
    which expects a function that takes a container (so other values may be referred to).
    In each case, you have to give the value a name.

    The value will be available as a normal member variable under this name.
    If given via a function, this function will only be evaluated when the value is accessed,
    and the value will be memoized, so the function won't be called twice.
    If the function raises an exception, then this will be memoized just as well.

    For instance,

    >>>> container = Container()
    >>>> container.add_function('pi', lambda _: 22/7)
    >>>> container.add_function('pi_squared', lambda c: c.pi * c.pi)
    >>>> assert container.pi_squared == 22/7 * 22/7
    """
    def __init__(self):
        self._values = {}
        self._functions = {}

    def __contains__(self, key):
        return key in self._values or key in self._functions

    def __getattr__(self, key):
        val = self._values.get(key)
        if val is None:
            # uncomment for super serious debugging
            # logger.debug(f'... {key}')
            try:
                ret = self._functions[key](self)
            except BaseException as e:
                val = (True, e)
            else:
                val = (False, ret)
            self._values[key] = val
        error, ret = val
        if error:
            raise ret
        return ret

    def add_function(self, name, fn):
        if name in self._functions:
            raise RuntimeError(f"fn {name} already registered")
        self._functions[name] = fn

    def add_value(self, name, value):
        if name in self._values:
            raise RuntimeError(f"value {name} already registered")
        self._values[name] = value


def run_preflight_checks(container, testcases):
    # make sure that we can connect to the cloud and that the user doesn't have elevated privileges
    # the former would lead to each testcase aborting with a marginally useful message;
    # the latter would lead to scs_0116_permissions aborting, which we don't want to single out
    try:
        conn = container.conn
        if "member" not in ensure_unprivileged(conn, quiet=True):
            raise RuntimeError("OpenStack user is missing member role.")
    except Exception:
        logger.critical("Please make sure that ~/.config/openstack/clouds.yaml exists and is correct!", exc_info=True)
        del testcases[:]  # it's no use running any testcases now
        return False

    invalid = []
    for testcase in testcases:
        if not testcase.startswith('scs-') and testcase != 'cleanup':
            invalid.append(testcase)
        if testcase not in container:
            invalid.append(testcase)
    if invalid:
        logger.critical(f"Invalid/unkown testcases detected: {invalid}")
        testcases[:] = [tc for tc in testcases if tc not in invalid]
        return False
    return True


def run_testcases(subject, testcases, *, cloud=None, uuid_=None):
    if uuid_ is None:
        uuid_ = str(uuid.uuid4())

    c = make_container(subject, cloud=cloud)
    log = []
    logging.root.addHandler(LogHandler(level=logging.DEBUG, log=log))

    attestations = [
        attest(subject, PREFLIGHT_PSEUDO, lambda: run_preflight_checks(c, testcases)),
    ] + [
        attest(subject, testcase, lambda: getattr(c, testcase))
        for testcase in testcases
    ]

    return {
        'uuid': uuid_,
        'creator': 'openstack_test.py v0.1.0',
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
@click.argument('subjects', nargs=-1, required=True, type=str)
def run(subjects, specpath, version, sections, tests, monitor_url):
    spec = load_spec(specpath)
    versions = select_versions(spec, version)
    title, all_testcase_ids = compile_testcases(
        spec, versions, sections=sections, tests=tests,
    )
    logger.info(f"{title}: {len(all_testcase_ids)} testcases")
    if len(subjects) > 1:
        run_multiple_subjects(STATE_PATH, subjects, all_testcase_ids, monitor_url)
        return
    subject = subjects[0]
    report = run_testcases(subject, all_testcase_ids)
    enter_report(STATE_PATH, report, monitor_url)
    scorecard = maintain_scorecard(STATE_PATH, report)
    print_prelim_summary(title, report, subject, versions, partial=sections or tests)


@cli.command()
@click.option('--monitor-url', 'monitor_url', type=str, default=MONITOR_URL)
@click.argument('uuid_', type=str)
@click.argument('subject', type=str)
def run0(uuid_, subject, monitor_url):
    # this command is supposed to be run concurrently, so no scorecard maintenance!
    all_testcase_ids = sys.stdin.read().splitlines()
    report = run_testcases(subject, all_testcase_ids, uuid_=uuid_)
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
                a.aggregate_version(subject, version, fixed_testcases=FIXED_TESTCASES)
            # compute {subject[0]}/{version.object}
            a.aggregate_subjects(version['object']['id'], subjects)
        else:
            a.aggregate_version(subjects[0], version, fixed_testcases=FIXED_TESTCASES)

    report = a.make_report()
    enter_report(STATE_PATH, report, monitor_url)
    maintain_scorecard(STATE_PATH, report)


@cli.command()
@click.argument('subjects', nargs=-1, required=True, type=str)
def cleanup(subjects):
    """
    clean up any lingering IaaS resources
    """
    if len(subjects) > 1:
        do_multiple_subjects('cleanup', subjects)
        return
    run_testcases(subjects[0], ('cleanup', ))


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    openstack.enable_logging(debug=False)
    cli()
