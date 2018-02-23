#!/usr/bin/env python

from __future__ import print_function

import click
import paramiko
import re
import yaml
import pprint
import os
import errno
import subprocess
from time import gmtime, strftime
from collections import namedtuple
from openshift_audit import *

pass_runtime = click.make_pass_decorator(Runtime)
context_settings = dict(help_option_names=['-h', '--help'])

# This map will be populated to contain cluster_name->{ "alias"->"literal" }
# Each key of the dict is an alias that will exist in all cluster equivalent
# dicts.
equivalents = {
}

output_repo = None

timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime())

@click.group(context_settings=context_settings)
@click.pass_context
def cli(ctx, **kwargs):
    # @pass_runtime
    ctx.obj = Runtime(**kwargs)


def split(equivalent):
    alias, pair = equivalent.split(":")
    left, right = pair.split("=")
    a_split = namedtuple('AnEquivalent', 'alias left right')
    return a_split(alias=alias, left=left, right=right)


def normalize_string(cluster, s):
    for alias, match in equivalents[cluster].iteritems():
        s = s.replace(match, alias)

    # If you see ###.###(.###...###), assume it is an IP address or version and normalize it.
    s = re.subn(r'\d+\.\d+(\.\d+)*', 'NUM_FIELD', s, 1000)[0]
    s = s.replace("NUM_FIELD-NUM_FIELD", "NUM_FIELD")  # versions with releases should be same as versions
    return s


# Examine the parameter and replaces lists with a map IFF
# the list appears to be translatable into a lossless map. The
# reason for this is that maps can be more easily & deeply compared
# than lists because they don't try to preserve order.
def delistify(model):

    if isinstance(model, dict):
        nm = Model()
        for k, v in model.iteritems():
            nm[k] = delistify(v)

        if nm.name is not Missing and nm.value is not Missing and ( "PASS" in nm.name.upper() or "SECRET" in nm.name.upper() ):
            nm.value = "*********"

        return nm

    if isinstance(model, list):

        # This appears to be a list which can be turned into a map for easier comparison
        if len(model) > 0 and isinstance(model[0], dict) and 'name' in model[0]:
            nm = Model()
            for e in model:
                nm[e['name']] = delistify(e)
            return nm

        # Otherwise, this is a normal list we don't know how to improve
        nl = ListModel()
        for e in model:
            nl.append(delistify(e))

    # Otherwise, this is probably just a primitive
    return model


def plant(hostpair, path_components, name, model):
    base = ["audit"]
    base.extend(path_components)
    path = os.path.join(*base)
    try:
        print("making: {}".format(path))
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

    model = delistify(model)

    y = normalize_string(hostpair, yaml.dump(model.primitive()))
    filepath = os.path.join(path, name)
    with open(filepath, "w+") as f:
        print("writing: {}".format(filepath))
        f.write(y)


def read_resource(hostpair, project, kind, name):
    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostpair.split(':')[-1], username='root')
        _, stdout_stream, stderr = client.exec_command('oc get {} {} -n {} -o=yaml'.format(kind, name, project))
        model = Model(yaml.load(stdout_stream.read()))

        model.pop("apiVersion", None)
        model.pop("metadata", None)
        model.pop("status", None)

        plant(hostpair, [project, kind], name, model)


def read_master_config(hostpair):
    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostpair.split(':')[-1], username='root')
        _, stdout_stream, stderr = client.exec_command('cat /etc/origin/master/master-config.yaml')
        model = Model(yaml.load(stdout_stream.read()))

        model.pop("corsAllowedOrigins", None)
        if model.routingConfig.subdomain is not Missing:
            del model.routingConfig["subdomain"]
        if model.etcdClientInfo.urls is not Missing:
            del model.etcdClientInfo["urls"]

        plant(hostpair, ["master"], "config", model)


@cli.command("master:scan-config", short_help="Scan and report differences in master config")
@click.argument("host", metavar="ALIAS@hostname", nargs=-1)
@click.option("-r", "--repodir", required=True, metavar='DIR')
@click.option("-e", "--equivalent", default=[], metavar='ALIAS:LEFT=RIGHT', multiple=True,
              help="Make two strings equivalent when comparing resources")
@pass_runtime
def master_scan_config(runtime, host, repodir, equivalent):
    global output_repo

    if len(host) < 2:
        click.echo("At least two hostnames must be specified")
        exit(1)

    if not os.path.isdir(repodir):
        click.echo("Must be a git repository: {}".format(repodir))
        exit(1)

    output_repo = repodir
    os.chdir(output_repo)
    subprocess.check_call(['git', 'fetch', 'origin'])
    subprocess.check_call(['git', 'checkout', 'master'])

    for hostpair in host:
        equivalents[hostpair] = {}
        alias, hostname = hostpair.split(":")
        # Delete the local branch if it exists
        subprocess.call(['git', 'branch', '-d', alias])

        # Try to access an existing remote branch
        r = subprocess.call(['git', 'checkout', '-B', alias, "origin/{}".format(alias)])
        if r != 0:
            # No remote tracking branch, so create it locally
            subprocess.check_call(['git', 'checkout', '-B', alias])
            # Make an initial commit
            subprocess.check_call(['git', 'commit', '-m', "Initial", "--allow-empty"])
            # Setup tracking
            subprocess.check_call(['git', 'push', '-u', 'origin', alias])

    for e in equivalent:
        alias, pair = e.split(":")
        split = pair.split("=")
        for idx, s in enumerate(split):
            equivalents[host[idx]][alias] = s

    pp = pprint.PrettyPrinter(indent=4)

    pp.pprint(equivalents)

    primary_alias, primary_hostname = host[0].split(":")

    for hostpair in host:
        alias, hostname = hostpair.split(":")

        os.chdir(output_repo)
        # Checkout this cluster's branch
        subprocess.check_call(['git', 'checkout', alias])

        if primary_alias == alias:
            subprocess.check_call(['git', 'reset', '--hard', 'origin/master'])
        else:
            subprocess.check_call(['git', 'reset', '--hard', 'origin/{}'.format(primary_alias)])

        # Create the commit we will be dealing with
        subprocess.check_call(['git', 'add', '-A', '.'])
        subprocess.check_call(['git', 'commit', '-m', "Audit {}".format(timestamp), "--allow-empty"])

        read_master_config(hostpair)
        read_resource(hostpair, "openshift-web-console", "configmap", "webconsole-config")
        read_resource(hostpair, "default", "dc", "router")
        read_resource(hostpair, "default", "dc", "docker-registry")

        subprocess.check_call(['git', 'add', '-A', '.'])
        subprocess.check_call(['git', 'commit', '--amend', '--no-edit', '--allow-empty'])
        subprocess.check_call(['git', 'push', '-u', 'origin', alias, '--force'])

    exit(1)


    #m1 = read_master_config('54.147.205.250')  # free-int
    #m2 = read_master_config('52.14.8.110')  # free-stg

    # m2 = read_master_config('35.182.64.49', equivalent, right=True)  # ca-central-1
    #
    # ignore = {
    #     "root['corsAllowedOrigins']",
    #     "root['routingConfig']['subdomain']",
    #     "root['etcdClientInfo']['urls']",
    # }
    #
    # print("Master Config")
    # d = DeepDiff(m1, m2, ignore_order=True, exclude_paths=ignore)
    # pp.pprint(d)
    #
    # m1 = read_resource('54.227.14.142', "openshift-webc-console", "configmap", "web-console-config", equivalent)  # east-1
    # m2 = read_resource('35.182.64.49', "openshift-webc-console", "configmap", "web-console-config", equivalent, right=True)  # ca-central-1
    # d = DeepDiff(m1, m2, ignore_order=True, exclude_paths=ignore)
    # print("Web Console Config")
    # pp.pprint(d)
    #
    # m1 = read_resource('54.227.14.142', "default", "dc", "registry", equivalent)  # east-1
    # m2 = read_resource('35.182.64.49', "default", "dc", "registry", equivalent, right=True)  # ca-central-1
    # d = DeepDiff(m1, m2, ignore_order=True, exclude_paths=ignore)
    # print("Registry")
    # pp.pprint(d)
    #
    # ignore = {
    #     "root['status']",
    #     "root['metadata']",
    #     "root['spec']['template']['spec']['containers']",
    #     "root['apiVersion']",
    # }
    #
    # m1 = read_resource('54.227.14.142', "default", "dc", "router", equivalent)  # east-1
    # m2 = read_resource('35.182.64.49', "default", "dc", "router", equivalent, right=True)  # ca-central-1
    # d = DeepDiff(m1, m2, ignore_order=True, exclude_paths=ignore)
    # print("Router")
    # pp.pprint(d)
    #
    # d = DeepDiff(m1['spec']['template']['spec']['containers'][0], m2['spec']['template']['spec']['containers'][0], ignore_order=True, exclude_paths=ignore)
    # print("Router Container")
    # pp.pprint(d)
    #
    #
    #
    # pass

if __name__ == '__main__':
    cli(obj={})

