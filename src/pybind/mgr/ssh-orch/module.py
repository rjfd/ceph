# -*- coding: utf-8 -*-

from __future__ import absolute_import

import errno
import fnmatch
import json
import os
import random
import re
import select
import time
from io import StringIO

from threading import Thread, Event, RLock
from collections import defaultdict

from paramiko import client, RSAKey

from mgr_module import MgrModule, HandleCommandResult, CLIReadCommand, CLIWriteCommand
import orchestrator as orch


logger = None  # will be populated with the mgr module logger instance


class SshCommandCompletion(object):
    def __init__(self, hostname, channel):
        self.hostname = hostname
        self._channel = channel
        self._channel._completion = self

    @property
    def channel(self):
        return self._channel

    @property
    def result(self):
        out = self._channel.makefile("r", -1)
        err = self._channel.makefile_stderr("r", -1)
        out = out.readlines()
        err = err.readlines()
        return self._channel.recv_exit_status(), \
               "".join(out) if out else "".join(err)


class Host(object):
    def __init__(self, address, username, ssh_key_path, ssh_key):
        self.hostname = None
        addr, port = self._parse_address(address)
        self.address = addr
        self.port = port
        self.username = username
        self.ssh_key_path = ssh_key_path
        self.ssh_key = ssh_key
        self.lock = RLock()
        self.ssh_client = client.SSHClient()
        self.ssh_client.set_missing_host_key_policy(client.WarningPolicy)
        self._connected = False
        self.error = None

    @classmethod
    def _parse_address(cls, address):
        colon_idx = address.find(":")
        if colon_idx == -1:
            return address, 22
        return address[:colon_idx], int(address[colon_idx+1:])

    @property
    def connected(self):
        with self.lock:
            if not self._connected:
                return False
            try:
                transport = self.ssh_client.get_transport()
                if not transport.is_active():
                    return False
                transport.send_ignore()
                return True
            except Exception:
                return False

    def _connect(self):
        with self.lock:
            try:
                logger.debug("[SSH:%s] connecting...", self.address)
                if self.ssh_key:
                    ios = StringIO(self.ssh_key)
                    pkey = RSAKey.from_private_key(ios)
                    ios.close()
                else:
                    pkey = None

                self.ssh_client.connect(self.address, username=self.username,
                                        pkey=pkey,
                                        key_filename=self.ssh_key_path,
                                        allow_agent=False, timeout=10)
                self.ssh_client.get_transport().set_keepalive(5)
                self._connected = True
                self.error = None
                res, out = self.run("hostname")
                self.hostname = out.strip() if res else self.address
                logger.info("[SSH:%s] successfully connected", self.hostname)
            except Exception as ex:
                logger.exception(ex)
                self.error = str(ex)
                logger.debug("[SSH:%s] connect failed: %s", self.address, self.error)
                self._connected = False

    def __del__(self):
        with self.lock:
            if self._connected:
                self.ssh_client.close()

    def run(self, command):
        with self.lock:
            if not self._connected:
                raise Exception(self.error if self.error else "not connected")
            _, out, err = self.ssh_client.exec_command(command)
            err = err.readlines()
            out = out.readlines()
            if err:
                return False, "".join(err)
            return True, "".join(out)

    def run_async(self, command):
        with self.lock:
            if not self._connected:
                raise Exception(self.error if self.error else "not connected")
            channel = self.ssh_client.get_transport().open_session()
            channel.exec_command(command)
            return SshCommandCompletion(self.hostname, channel)

    def reconnect(self):
        with self.lock:
            logger.debug("[SSH:%s] reconnecting",
                        self.hostname if self.hostname else self.address)
            if self._connected:
                logger.info("[SSH:%s] Closing connection...", self.hostname)
                self.ssh_client.close()
                self._connected = False
            self._connect()
            return self.connected


class InstantaneousCompletion(orch.ReadCompletion):
    def __init__(self, result):
        super(InstantaneousCompletion, self).__init__()
        self._result = result

    @property
    def result(self):
        return self._result

    @property
    def is_complete(self):
        return True

    @property
    def is_running(self):
        return True


class RunSshCommandsMixin(Thread):
    def __init__(self, hosts, commands):
        super(RunSshCommandsMixin, self).__init__()
        self._hosts = hosts
        self._commands = commands
        self._results = defaultdict(list)
        self._running = False
        self._exception = None
        self._complete = False

    def start(self):
        self._running = True
        super(RunSshCommandsMixin, self).start()

    def run(self):
        try:
            retcodeByHost = {}
            for host in self._hosts:
                retcodeByHost[host.hostname] = 0
            completions = []
            for command in self._commands:
                for host in self._hosts:
                    if retcodeByHost[host.hostname] > 0:
                        # don't execute more commands in this host
                        continue
                    logger.info("[SSH:%s] run: %s", host.hostname, command)
                    completions.append(host.run_async(command))

                while completions:
                    r, _, _ = select.select([comp.channel for comp in completions],
                                            [], [], 5.0)
                    for channel in r:
                        comp = channel._completion
                        completions.remove(comp)
                        res, out = comp.result
                        retcodeByHost[comp.hostname] = res
                        self._results[comp.hostname].append((res, out))
                        logger.info("[SSH:%s] retcode: %s output:\n%s", comp.hostname, res, out)

            for host, results in self._results.items():
                self.handle_commands_complete(host, results)
        except Exception as ex:
            logger.exception(ex)
            self._exception = ex
        finally:
            self._complete = True

    def handle_commands_complete(self, hostname, results):
        raise NotImplementedError()

    @property
    def is_running(self):
        return self._running

    @property
    def is_complete(self):
        return self._complete


class SshReadCompletion(RunSshCommandsMixin, orch.ReadCompletion):
    def __init__(self, hosts, commands):
        super(SshReadCompletion, self).__init__(hosts, commands)
        self._result = []

    def handle_commands_complete(self, hostname, results):
        raise NotImplementedError()

    @property
    def result(self):
        # pylint: disable=E0702
        if self._exception:
            raise self._exception
        return self._result


class SshWriteCompletion(RunSshCommandsMixin, orch.WriteCompletion):
    def __init__(self, hosts, commands):
        super(SshWriteCompletion, self).__init__(hosts, commands)

    def handle_commands_complete(self, hostname, results):
        pass

    @property
    def is_persistent(self):
        # pylint: disable=E0702
        if self._exception:
            raise self._exception
        return self._complete

    @property
    def is_effective(self):
        return True


class InventoryCompletion(SshReadCompletion):
    def __init__(self, hosts):
        super(InventoryCompletion, self).__init__(
            hosts, ["lsblk --list -b --output NAME,TYPE,SIZE,ROTA | sed -n '1!p'"])

    def handle_commands_complete(self, hostname, results):
        invnode = orch.InventoryNode(hostname, [])
        self._result.append(invnode)
        res, out = results[0]
        if res == 0:
            lines = [e.strip() for e in out.split("\n") if e]
            for line in lines:
                disk = [e.strip() for e in line.split(" ") if e]
                assert(len(disk) == 4)
                logger.debug("[SSH:%s] found disk: %s", hostname, disk)
                if disk[1] == 'disk':
                    dev = orch.InventoryDevice()
                    dev.blank = True
                    dev.type = "hdd" if disk[3] == '1' else "ssd"
                    dev.id = disk[0]
                    dev.size = int(disk[2])
                    invnode.devices.append(dev)
                elif disk[1] == 'part':
                    if invnode.devices[len(invnode.devices)-1].id in disk[0]:
                        invnode.devices[len(invnode.devices)-1].blank = False


class GetNFSServiceStatusCompletion(SshReadCompletion):
    def __init__(self, hosts):
        super(GetNFSServiceStatusCompletion, self).__init__(
            hosts, [
                "type ganesha.nfsd",
                "sudo ganesha.nfsd -v",
                "grep %url /etc/ganesha/ganesha.conf",
                "sudo systemctl is-active nfs-ganesha"
            ])
        self._service_type = "nfs"
        self._service = "nfs-ganesha"

    def handle_commands_complete(self, hostname, results):
        res, out = results[0]
        if res == 1:  # ganesha.nfsd does not exist in this host
            return

        desc = orch.ServiceDescription()
        desc.nodename = hostname
        desc.service_type = self._service_type
        desc.daemon_name = self._service
        desc.container_id = None

        res, out = results[1]
        if res == 0 and out.strip():
            va = out.strip().split("=")
            if len(va) == 2:
                desc.version = va[1].strip()
            else:
                desc.version = out.strip()

        res, out = results[2]
        if res == 0 and out.strip():
            out = out.strip()
            if out.find("%url") == 0:
                desc.rados_config_location = out[5:]

        if len(results) > 3:
            res, out = results[3]
            if res == 0 and out.strip() == "active":
                desc.status = 1
            elif res == 3 and out.strip() == "failed":
                # extract erro description
                desc.status = -1
            else:
                desc.status = 0
        else:
            desc.status = 0

        self._result.append(desc)


class Module(MgrModule, orch.Orchestrator):
    def __init__(self, *args, **kwargs):
        super(Module, self).__init__(*args, **kwargs)
        self.run = False
        self.stopping = False
        self.hosts = []
        global logger
        logger = self.log

    def serve(self):
        logger.info('Started')

        host_list = json.loads(self.get_store("_ssh_orch_host_list", "[]"))
        self.hosts = [Host(a, u, kf, k) for a, u, kf, k in host_list]

        self.run = True

        while self.run:
            for host in self.hosts:
                if not host.connected:
                    host.reconnect()
            time.sleep(1)

    def shutdown(self):
        self.run = False
        self.stopping = True
        self.log.info('Stopped')

    def _get_host(self, hostname):
        hosts = self._find_hosts(hostname)
        return hosts[0] if hosts else None

    def _find_hosts(self, hostname):
        return [h for h in self.hosts
                if not hostname or fnmatch.fnmatch(h.hostname, hostname)]

    def handle_command(self, inbuf, cmd):

        pass

    @CLIReadCommand("ssh-orch host ls",
                    desc="List hosts managed by ssh-orch orchestrator")
    def host_ls_cmd(self):
        host_list = json.loads(self.get_store("_ssh_orch_host_list", "[]"))
        out = ""
        for a, u, kf, _ in host_list:
            out += "address={}, username={}, key={}\n" \
                   .format(a, u, kf if kf else "<private_key>")
        if not out:
            return HandleCommandResult(odata="No hosts added yet.")
        return HandleCommandResult(odata=out)

    @CLIWriteCommand('ssh-orch host add',
                     'name=address,type=CephString '
                     'name=username,type=CephString '
                     'name=ssh-key-path,type=CephString,req=false',
                     'Add host to be managed by ssh-orch orchestrator')
    def host_add_cmd(self, address, username, ssh_key_path=None, inbuf=None):
        host_list = json.loads(self.get_store("_ssh_orch_host_list", "[]"))

        if len([a for a, _, _, _ in host_list if a == address]) > 0:
            return HandleCommandResult(
                -errno.EEXIST, rs="Host '{}' already added".format(address))

        if not ssh_key_path:
            # check if ssh_key was passed in inbuf
            if not inbuf:
                return HandleCommandResult(
                    -errno.ENOENT, rs="No SSH key was secified")
        elif not os.path.isfile(ssh_key_path) and not os.path.islink(ssh_key_path):
            return HandleCommandResult(
                -errno.ENOENT, rs="SSH key file '{}' does not exist".format(ssh_key_path))

        host_list.append((address, username, ssh_key_path, inbuf))
        self.set_store("_ssh_orch_host_list", json.dumps(host_list))
        self.hosts.append(Host(address, username, ssh_key_path, inbuf))
        return HandleCommandResult(odata="Host '{}' added".format(address))

    @CLIWriteCommand('ssh-orch host rm',
                     'name=address,type=CephString',
                     'Remove host from ssh-orch orchestrator')
    def host_rm_cmd(self, address):
        host_list = json.loads(self.get_store("_ssh_orch_host_list", "[]"))

        found = -1
        for i, (a, _, _, _) in enumerate(host_list):
            if a == address:
                found = i
                break

        if found == -1:
            return HandleCommandResult(
                -errno.ENOENT, rs="Host '{}' is not managed".format(address))

        del host_list[i]
        self.set_store("_ssh_orch_host_list", json.dumps(host_list))
        del self.hosts[[i for i, h in enumerate(self.hosts) if h.address == address][0]]

        return HandleCommandResult(odata="Host '{}' removed".format(address))

    @CLIWriteCommand('ssh-orch host reconnect',
                     'name=address,type=CephString,req=false',
                     'Reconnect host(s)')
    def host_reconnect_cmd(self, address=None):
        errors = []
        for host in [h for h in self.hosts if not address or h.address == address]:
            if not host.reconnect():
                errors.append("{}: {}".format(host.address, host.error))
        if not errors:
            return HandleCommandResult(
                odata="All {} hosts connected".format(len(self.hosts)))
        return HandleCommandResult(
            odata="Could not connect to some hosts:\n{}".format("\n".join(errors)))

    @CLIReadCommand('ssh-orch host status',
                    'name=address,type=CephString,req=false',
                    'Show host(s) connection status')
    def host_status_cmd(self, address=None):
        if not self.hosts:
            return HandleCommandResult(odata="No hosts added yet.")
        out = "\n".join(
            ["{}: {}".format(h.address, "Connected ({})".format(h.hostname)
                if h.connected else "Not connected ({})".format(h.error)
                if h.error else "Not connected")
                for h in self.hosts if not address or h.address == address])
        return HandleCommandResult(odata=out)

    # Orchestrator implementation functions

    def available(self):
        if not self.run:
            return False, "Shutting down..." if self.stopping else "Initializing..."
        errors = []
        for n in self.hosts:
            if not n.connected:
                errors.append(n.error)
        if errors:
            return True, "\n".join(errors)
        else:
            return True, "Connected to all hosts ({} hosts)".format(
                len(self.hosts))

    def wait(self, completions):
        for comp in completions:
            if not comp.is_running:
                comp.start()

        time.sleep(1.0)  # some operations complete in less than 1 second
        return all([comp.is_complete for comp in completions])

    def get_inventory(self, node_filter=None):
        if node_filter:
            node_filter = node_filter.nodes
        logger.info("collecting inventory...")
        return InventoryCompletion(
            [node for node in self.hosts if node_filter is None or node.hostname in node_filter])

    def add_stateless_service(self, service_type, spec):
        logger.info("adding stateless service of type: %s", service_type)

        if service_type == "nfs":
            selected_hosts = []
            if spec.placement.label is None:
                # choose a node randomly
                selected_hosts.append(random.randint(0, len(self.hosts)-1))
            else:
                selected_hosts = self._find_hosts(spec.placement.label)

            return SshWriteCompletion(selected_hosts, ["sudo systemctl start nfs-ganesha"])

        raise NotImplementedError()

    def describe_service(self, service_type=None, service_id=None, node_name=None):
        logger.info("collecting service info of type: %s", service_type)

        if service_type is None:
            return GetNFSServiceStatusCompletion(self._find_hosts(node_name))

        if service_type == "nfs":
            return GetNFSServiceStatusCompletion(self._find_hosts(node_name))

        raise NotImplementedError()

    def remove_stateless_service(self, service_type, id_):
        logger.info("removing stateless service of type %s on %s", service_type, id_)

        if service_type == "nfs":
            return SshWriteCompletion(self._find_hosts(id_),
                                      ["sudo systemctl stop nfs-ganesha"])

        raise NotImplementedError()

    def update_stateless_service(self, service_type, id_, spec):
        logger.info("updating stateless service of type %s on %s", service_type, id_)

        if service_type == "nfs":
            return SshWriteCompletion(self._find_hosts(id_),
                                      ["sudo systemctl stop nfs-ganesha"
                                       " && sudo systemctl start nfs-ganesha"])

        raise NotImplementedError()

    def add_mon(self, node_name):
        logger.info("adding a monitor to %s", node_name)

        host = self._get_host(node_name)
        dot_idx = host.hostname.find(".")
        mon_id = host.hostname[:dot_idx] if dot_idx > 0 else host.hostname
        return SshWriteCompletion(
            [host],
            [
                "! sudo systemctl is-active ceph-mon@{}".format(mon_id),
                "sudo rm -rf /var/lib/ceph/mon/ceph-{}".format(mon_id),
                "sudo mkdir -p /var/lib/ceph/mon/ceph-{}".format(mon_id),
                "sudo ceph auth get mon. -o /tmp/__mon_keyring",
                "sudo ceph mon getmap -o /tmp/__mon_map",
                "sudo ceph-mon -i {} --mkfs --monmap /tmp/__mon_map --keyring /tmp/__mon_keyring".format(mon_id),
                "sudo rm -f /tmp/__mon_keyring /tmp/__mon_map",
                "sudo chown -R ceph:ceph /var/lib/ceph",
                "echo '[mon.{}]' | sudo tee -a /etc/ceph/ceph.conf "
                "&& echo 'host = {}' | sudo tee -a /etc/ceph/ceph.conf "
                "&& echo 'mon addr = {}' | sudo tee -a /etc/ceph/ceph.conf".format(mon_id, host.hostname, host.address),
                "sudo systemctl start ceph-mon@{}".format(mon_id)
            ]
        )

    def remove_mon(self, node_name):
        logger.info("removing monitor from %s", node_name)
        host = self._get_host(node_name)
        dot_idx = host.hostname.find(".")
        mon_id = host.hostname[:dot_idx] if dot_idx > 0 else host.hostname
        return SshWriteCompletion(
            [host],
            [
                "sudo systemctl is-active ceph-mon@{}".format(mon_id),
                "sudo systemctl stop ceph-mon@{}".format(mon_id),
                "sudo rm -rf /var/lib/ceph/mon/ceph-{}".format(mon_id),
                "B=`sudo grep -n 'mon\\.node1' /etc/ceph/ceph.conf | cut -f 1 -d ':'` "
                "&& [ ! -z $B ] "
                "&& E=`sudo tail -n +$((B + 1)) /etc/ceph/ceph.conf | grep -n '^\\[' | cut -f 1 -d ':'` "
                "&& if [ -z $E ]; then E='$'; else E=$((B + E -1)); fi "
                "&& sudo sed -i /etc/ceph/ceph.conf -re \"$B,${E}d\"",
                "sudo ceph mon remove {}".format(mon_id)
            ]
        )
