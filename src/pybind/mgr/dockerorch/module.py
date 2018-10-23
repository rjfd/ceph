# vim: ts=8 et sw=4 sts=4
"""
ceph-mgr ceph-dev-docker orchestrator module
"""
from __future__ import absolute_import

import json
import errno
import requests
import time

from subprocess import Popen, PIPE
from threading import Event, Thread

from mgr_module import MgrModule
import orchestrator


CEPH_DIR_PATH = "/home/rdias/Work/ceph"


class ShellCmdCompletion(orchestrator.WriteCompletion):
    def __init__(self, service, cmd):
        self.service = service
        self.cmd = cmd
        self.ret = None
        self.out = None

    def execute(self):
        proc = Popen(self.cmd, stdout=PIPE)
        out, _ = proc.communicate()
        self.ret = proc.returncode
        if self.ret == 0:
            self.out = out.strip()

    @property
    def is_errored(self):
        assert self.ret is not None
        return self.ret != 0

    @property
    def is_persistent(self):
        return self.ret == 0

    @property
    def is_effective(self):
        return self.ret == 0


class DockerInfoCompletion(ShellCmdCompletion):
    def __init__(self):
        super(DockerInfoCompletion, self).__init__("nfs",
                ['docker', 'ps', '-f', 'name=nfs-ganesha', '-q'])
        self.container_id = None
        self.container_addr = None

    def execute(self):
        super(DockerInfoCompletion, self).execute()
        assert self.ret == 0
        container_id = self.out.decode("utf-8").strip()
        if container_id:
            self.cmd = ['docker', 'inspect', container_id, '-f',
                        '{{json .NetworkSettings.Networks }}']
            self.ret = None
            self.out = None
            super(DockerInfoCompletion, self).execute()
            assert self.ret == 0
            net = json.loads(self.out.decode("utf-8").strip())

            self.container_id = container_id
            self.container_addr = net['bridge']['IPAddress']

    def get_result(self):
        if self.container_id and self.container_addr:
            return {
                'container_id': self.container_id,
                'address': self.container_addr
            }
        return None


class DockerOrchestrator(MgrModule, orchestrator.Orchestrator):
    OPTIONS = [
    ]


    COMMANDS = [
    ]

    def __init__(self, *args, **kwargs):
        super(DockerOrchestrator, self).__init__(*args, **kwargs)
        self.run = False


    def available(self):
        return True, ""


    def handle_command(self, inbuf, cmd):
        pass


    def serve(self):
        self.log.info('ceph-dev-docker orch starting')
        while self.run:
            time.sleep(1)


    def shutdown(self):
        self.log.info('ceph-dev-docker orch shutting down')
        self.run = False

    def wait(self, completions):
        for comp in completions:
            assert isinstance(comp, ShellCmdCompletion)
            self.log.info("Executing shell cmd: %s", comp.cmd)
            comp.execute()
            self.log.info("Finished shell cmd with retcode=%s", comp.ret)
        return True

    def add_stateless_service(self, service_type, spec):
        if service_type == "nfs":
            return ShellCmdCompletion(service_type,
                                      ["docker", "run", "-d", "--init", "--rm",
                                       "-v", "{}:/ceph".format(CEPH_DIR_PATH),
                                       "-p", "2049:2049",
                                       "--cap-add", "SYS_ADMIN",
                                       "--cap-add", "DAC_READ_SEARCH",
                                       "--name", "nfs-ganesha",
                                       "nfs-ganesha-docker"])
        else:
            raise NotImplementedError()

    def update_stateless_service(self, service_type, id_, spec):
        assert isinstance(spec, orchestrator.StatelessServiceSpec)
        raise NotImplementedError()

    def remove_stateless_service(self, service_type, id_):
        if service_type == "nfs":
            return ShellCmdCompletion(service_type,
                                      ["docker", "kill", "nfs-ganesha"])
        else:
            raise NotImplementedError()

    def describe_service(self, service_type, service_id):
        if service_type == "nfs":
            return DockerInfoCompletion()
        else:
            raise NotImplementedError()
