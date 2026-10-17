#!/usr/bin/env python3
import os.path

import yaml

from plugin.plugin_clusterstacks import PluginClusterStacks
from plugin.plugin_gardener import PluginGardener
from plugin.plugin_kind import PluginKind
from plugin.plugin_static import PluginStatic
from plugin.plugin_t8s import PluginT8s


PLUGIN_LOOKUP = {
    "clusterstacks": PluginClusterStacks,
    "gardener": PluginGardener,
    "kind": PluginKind,
    "static": PluginStatic,
    "t8s": PluginT8s,
}
CONFIG_PATH = os.path.join(os.path.expanduser('~'), '.config', 'scs')
CLUSTERS_PATH = os.path.join(CONFIG_PATH, 'clusters.yaml')


def load_config(path=CLUSTERS_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as fileobj:
        cfg = yaml.load(fileobj, Loader=yaml.SafeLoader)
    if not isinstance(cfg, dict):
        raise RuntimeError('clusters.yaml must be a YAML dict')
    if 'clusters' not in cfg or not isinstance(cfg['clusters'], dict):
        raise RuntimeError('clusters.yaml must be a YAML dict, and so must be .clusters')
    return cfg


def init_plugin(cluster_id, statedir):
    cfg = load_config(CLUSTERS_PATH)
    spec = cfg['clusters'][cluster_id]
    config = spec['config']
    config.setdefault('name', cluster_id)
    cwd = os.path.abspath(os.path.join(statedir, cluster_id))
    plugin_maker = PLUGIN_LOOKUP.get(spec['kind'])
    if plugin_maker is None:
        raise ValueError(f"unknown plugin '{spec['kind']}'")
    os.makedirs(cwd, exist_ok=True)
    return plugin_maker(config, basepath=CONFIG_PATH, cwd=cwd)

