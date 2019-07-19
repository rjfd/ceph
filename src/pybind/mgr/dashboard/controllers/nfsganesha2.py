# -*- coding: utf-8 -*-
from __future__ import absolute_import

from typing import Sequence
from functools import partial


from . import ApiController, RESTController, Task, ControllerDoc
from .model import RequestModel as Model, validator as Val, attribute as Attr
from ..security import Scope
from ..services.exception import serialize_dashboard_exception
from ..services.ganesha import Ganesha, GaneshaConf, NFSException, Export, CephFSFSal, RGWFSal, \
                               Client


class FsalModel(Model):
    name = Attr.String(
        description="Export path",
        validator=Val.Enum("CEPH", "RGW"))

    user_id = Attr.String(
        description="CephX user ID",
        validator=(Val.NotEmpty(), Val.Length(64), ),
        required=False)

    filesystem = Attr.String(
        description="CephFS filesystem ID",
        validator=(Val.NotEmpty(), Val.Length(64), ),
        required=False)

    sec_label_xattr = Attr.String(
        description="Name of xattr for security label",
        validator=(Val.NotEmpty(), Val.Length(64), ),
        required=False)

    rgw_user_id = Attr.String(
        description="RGW user ID",
        validator=(Val.NotEmpty(), Val.Length(64), ),
        required=False)


class ClientModel(Model):
    addresses = Attr.ListOf(
        Model.String(validator=(Val.NotEmpty(), Val.Length(64), Val.IPAddress())),
        description="List of IP addresses")

    access_type = Attr.String(
        description="Client access type",
        validator=Val.Enum("RW", "RO", "MDONLY", "MDONLY_RO", "NONE"))

    squash = Attr.String(
        description="Client squash policy",
        validator=Val.Enum("no_root_squash", "root_id_squash", "root_squash", "all_squash"))


class CreateExportModel(Model):
    path = Attr.String(
        description="Export path",
        validator=Val.Regex())

    cluster_id = Attr.String(
        description="Cluster identifier")

    daemons = Attr.ListOf(
        Model.String(validator=Val.Length(64)),
        description="List of NFS Ganesha daemons identifiers")

    pseudo = Attr.String(
        description="Pseudo FS path",
        validator=Val.Regex(),
        required=False)

    tag = Attr.String(
        description="NFSv3 export tag",
        validator=Val.NotEmpty())

    access_type = Attr.String(
        description="Export access type",
        validator=Val.Enum("RW", "RO", "MDONLY", "MDONLY_RO", "NONE"))

    squash = Attr.String(
        description="Export squash policy",
        validator=Val.Enum("no_root_squash", "root_id_squash", "root_squash", "all_squash"))

    security_label = Attr.String(
        description="Security label",
        validator=Val.Length(64))

    protocols = Attr.ListOf(
        Model.Int(validator=Val.Enum(3, 4)),
        description="List of protocol types")

    transports = Attr.ListOf(
        Model.String(validator=Val.Enum("TCP", "UDP")),
        description="List of transport types")

    fsal = Attr.Model(FsalModel,
                      description="FSAL configuration")

    clients = Attr.ListOf(
        Attr.Model(ClientModel),
        description="List of client configurations",
        required=False)

    reload_daemons: Attr.Bool(
        description="Trigger reload of NFS-Ganesha daemons configuration",
        required=False)


class ExportModel(CreateExportModel):
    export_id = Attr.Int(
        description="Export ID",
        validator=Val.Gt(0))


def model_from_service_export(export: Export) -> ExportModel:
    model = ExportModel(export_id=export.export_id,
                        cluster_id=export.cluster_id,
                        path=export.path,
                        daemons=sorted([d for d in export.daemons]),
                        pseudo=export.pseudo,
                        tag=export.tag,
                        access_type=export.access_type,
                        squash=export.squash,
                        security_label=export.security_label,
                        protocols=sorted([p for p in export.protocols]),
                        transports=sorted([t for t in export.transports]))

    model.fsal = FsalModel(name=export.fsal.name)
    if isinstance(export.fsal, CephFSFSal):
        model.fsal.user_id = export.fsal.user_id
        model.fsal.filesystem = export.fsal.fs_name
        model.fsal.sec_label_xattr = export.fsal.sec_label_xattr
    elif isinstance(export.fsal, RGWFSal):
        model.fsal.rgw_user_id = export.fsal.rgw_user_id

    for client in export.clients:
        model.clients.append(ClientModel(addresses=client.addresses,
                                         access_type=client.access_type,
                                         squash=client.squash))

    return model


def service_export_from_model(model: CreateExportModel) -> Export:
    if model.fsal.name == "CEPH":
        fsal = CephFSFSal(name=model.fsal.name,
                          user_id=model.fsal.user_id,
                          fs_name=model.fsal.filesystem,
                          sec_label_xattr=model.fsal.sec_label_xattr)
    elif model.fsal.name == "RGW":
        fsal = RGWFSal(name=model.fsal.name,
                       rgw_user_id=model.fsal.rgw_user_id)

    if model.clients:
        clients = [Client(client.addresses, client.access_type, client.squash)
                   for client in model.clients]
    else:
        clients = []

    export_id = model.export_id if isinstance(model, ExportModel) else None

    export = Export(export_id=export_id,
                    cluster_id=model.cluster_id,
                    path=model.path,
                    daemons=model.daemons,
                    pseudo=model.pseudo,
                    tag=model.tag,
                    access_type=model.access_type,
                    squash=model.squash,
                    security_label=model.security_label,
                    protocols=model.protocols,
                    transports=model.transports,
                    fsal=fsal,
                    clients=clients)
    return export


# pylint: disable=not-callable
def NfsTask(name, metadata, wait_for):
    def composed_decorator(func):
        return Task("nfs/{}".format(name), metadata, wait_for,
                    partial(serialize_dashboard_exception,
                            include_http_status=True))(func)
    return composed_decorator


@ApiController('/nfs-ganesha/export', Scope.NFS_GANESHA)
@ControllerDoc(group="NFS-Ganesha")
class NFSGaneshaExports(RESTController):
    RESOURCE_ID = "cluster_id/export_id"

    def list(self) -> Sequence[ExportModel]:
        result = []
        for cluster_id in Ganesha.get_ganesha_clusters():
            result.extend(
                [model_from_service_export(export)
                 for export in GaneshaConf.instance(cluster_id).list_exports()])
        return result

    def create(self, model: CreateExportModel) -> ExportModel:
        if model.fsal.name not in Ganesha.fsals_available():
            raise NFSException("Cannot create this export. "
                               "FSAL '{}' cannot be managed by the dashboard."
                               .format(model.fsal.name))

        ganesha_conf = GaneshaConf.instance(model.cluster_id)
        ex_id = ganesha_conf.create_export(service_export_from_model(model))
        if model.reload_daemons:
            ganesha_conf.reload_daemons(model.daemons)
        return model_from_service_export(ganesha_conf.get_export(ex_id))


# @ApiController('/nfs-ganesha', Scope.NFS_GANESHA)
# @ControllerDoc("NFS-Ganesha Management API", "NFS-Ganesha")
# class NFSGanesha(RESTController):

#     @EndpointDoc("Status of NFS-Ganesha management feature",
#                  responses={200: {
#                      'available': (bool, "Is API available?"),
#                      'message': (str, "Error message")
#                  }})
#     @Endpoint()
#     @ReadPermission
#     def status(self):
#         status = {'available': True, 'message': None}
#         try:
#             Ganesha.get_ganesha_clusters()
#         except NFSException as e:
#             status['message'] = str(e)
#             status['available'] = False

#         return status


# @ApiController('/nfs-ganesha/export', Scope.NFS_GANESHA)
# @ControllerDoc(group="NFS-Ganesha")
# class NFSGaneshaExports(RESTController):
#     RESOURCE_ID = "cluster_id/export_id"

#     @EndpointDoc("List all NFS-Ganesha exports",
#                  responses={200: [EXPORT_SCHEMA]})
#     def list(self):
#         result = []
#         for cluster_id in Ganesha.get_ganesha_clusters():
#             result.extend(
#                 [export.to_dict()
#                  for export in GaneshaConf.instance(cluster_id).list_exports()])
#         return result

#     @NfsTask('create', {'path': '{path}', 'fsal': '{fsal.name}',
#                         'cluster_id': '{cluster_id}'}, 2.0)
#     @EndpointDoc("Creates a new NFS-Ganesha export",
#                  parameters=CREATE_EXPORT_SCHEMA,
#                  responses={201: EXPORT_SCHEMA})
#     def create(self, path, cluster_id, daemons, pseudo, tag, access_type,
#                squash, security_label, protocols, transports, fsal, clients,
#                reload_daemons=True):
#         if fsal['name'] not in Ganesha.fsals_available():
#             raise NFSException("Cannot create this export. "
#                                "FSAL '{}' cannot be managed by the dashboard."
#                                .format(fsal['name']))

#         ganesha_conf = GaneshaConf.instance(cluster_id)
#         ex_id = ganesha_conf.create_export({
#             'path': path,
#             'pseudo': pseudo,
#             'cluster_id': cluster_id,
#             'daemons': daemons,
#             'tag': tag,
#             'access_type': access_type,
#             'squash': squash,
#             'security_label': security_label,
#             'protocols': protocols,
#             'transports': transports,
#             'fsal': fsal,
#             'clients': clients
#         })
#         if reload_daemons:
#             ganesha_conf.reload_daemons(daemons)
#         return ganesha_conf.get_export(ex_id).to_dict()

#     @EndpointDoc("Get an NFS-Ganesha export",
#                  parameters={
#                      'cluster_id': (str, 'Cluster identifier'),
#                      'export_id': (int, "Export ID")
#                  },
#                  responses={200: EXPORT_SCHEMA})
#     def get(self, cluster_id, export_id):
#         export_id = int(export_id)
#         ganesha_conf = GaneshaConf.instance(cluster_id)
#         if not ganesha_conf.has_export(export_id):
#             raise cherrypy.HTTPError(404)
#         return ganesha_conf.get_export(export_id).to_dict()

#     @NfsTask('edit', {'cluster_id': '{cluster_id}', 'export_id': '{export_id}'},
#              2.0)
#     @EndpointDoc("Updates an NFS-Ganesha export",
#                  parameters=dict(export_id=(int, "Export ID"),
#                                  **CREATE_EXPORT_SCHEMA),
#                  responses={200: EXPORT_SCHEMA})
#     def set(self, cluster_id, export_id, path, daemons, pseudo, tag, access_type,
#             squash, security_label, protocols, transports, fsal, clients,
#             reload_daemons=True):
#         export_id = int(export_id)
#         ganesha_conf = GaneshaConf.instance(cluster_id)

#         if not ganesha_conf.has_export(export_id):
#             raise cherrypy.HTTPError(404)

#         if fsal['name'] not in Ganesha.fsals_available():
#             raise NFSException("Cannot make modifications to this export. "
#                                "FSAL '{}' cannot be managed by the dashboard."
#                                .format(fsal['name']))

#         old_export = ganesha_conf.update_export({
#             'export_id': export_id,
#             'path': path,
#             'cluster_id': cluster_id,
#             'daemons': daemons,
#             'pseudo': pseudo,
#             'tag': tag,
#             'access_type': access_type,
#             'squash': squash,
#             'security_label': security_label,
#             'protocols': protocols,
#             'transports': transports,
#             'fsal': fsal,
#             'clients': clients
#         })
#         daemons = list(daemons)
#         for d_id in old_export.daemons:
#             if d_id not in daemons:
#                 daemons.append(d_id)
#         if reload_daemons:
#             ganesha_conf.reload_daemons(daemons)
#         return ganesha_conf.get_export(export_id).to_dict()

#     @NfsTask('delete', {'cluster_id': '{cluster_id}',
#                         'export_id': '{export_id}'}, 2.0)
#     @EndpointDoc("Deletes an NFS-Ganesha export",
#                  parameters={
#                      'cluster_id': (str, 'Cluster identifier'),
#                      'export_id': (int, "Export ID"),
#                      'reload_daemons': (bool,
#                                         'Trigger reload of NFS-Ganesha daemons'
#                                         ' configuration',
#                                         True)
#                  })
#     def delete(self, cluster_id, export_id, reload_daemons=True):
#         export_id = int(export_id)
#         ganesha_conf = GaneshaConf.instance(cluster_id)

#         if not ganesha_conf.has_export(export_id):
#             raise cherrypy.HTTPError(404)

#         export = ganesha_conf.remove_export(export_id)
#         if reload_daemons:
#             ganesha_conf.reload_daemons(export.daemons)


# @ApiController('/nfs-ganesha/daemon')
# @ControllerDoc(group="NFS-Ganesha")
# class NFSGaneshaService(RESTController):

#     @EndpointDoc("List NFS-Ganesha daemons information",
#                  responses={200: [{
#                      'daemon_id': (str, 'Daemon identifier'),
#                      'cluster_id': (str, 'Cluster identifier'),
#                      'status': (int,
#                                 'Status of daemon (1=RUNNING, 0=STOPPED, -1=ERROR',
#                                 True),
#                      'desc': (str, 'Error description (if status==-1)', True)
#                  }]})
#     def list(self):
#         status_dict = Ganesha.get_daemons_status()
#         if status_dict:
#             return [
#                 {
#                     'daemon_id': daemon_id,
#                     'cluster_id': cluster_id,
#                     'status': status_dict[cluster_id][daemon_id]['status'],
#                     'desc': status_dict[cluster_id][daemon_id]['desc']
#                 }
#                 for cluster_id in status_dict
#                 for daemon_id in status_dict[cluster_id]
#             ]

#         result = []
#         for cluster_id in Ganesha.get_ganesha_clusters():
#             result.extend(
#                 [{'daemon_id': daemon_id, 'cluster_id': cluster_id}
#                  for daemon_id in GaneshaConf.instance(cluster_id).list_daemons()])
#         return result


# @UiApiController('/nfs-ganesha')
# class NFSGaneshaUi(BaseController):
#     @Endpoint('GET', '/cephx/clients')
#     def cephx_clients(self):
#         return [client for client in CephX.list_clients()]

#     @Endpoint('GET', '/fsals')
#     def fsals(self):
#         return Ganesha.fsals_available()

#     @Endpoint('GET', '/lsdir')
#     def lsdir(self, root_dir=None, depth=1):
#         if root_dir is None:
#             root_dir = "/"
#         depth = int(depth)
#         if depth > 5:
#             logger.warning("[NFS] Limiting depth to maximum value of 5: "
#                            "input depth=%s", depth)
#             depth = 5
#         root_dir = '{}/'.format(root_dir) \
#                    if not root_dir.endswith('/') else root_dir

#         try:
#             cfs = CephFS()
#             paths = cfs.get_dir_list(root_dir, depth)
#             paths = [p[:-1] for p in paths if p != root_dir]
#             return {'paths': paths}
#         except (cephfs.ObjectNotFound, cephfs.PermissionError):
#             return {'paths': []}

#     @Endpoint('GET', '/cephfs/filesystems')
#     def filesystems(self):
#         return CephFS.list_filesystems()

#     @Endpoint('GET', '/rgw/buckets')
#     def buckets(self, user_id=None):
#         return RgwClient.instance(user_id).get_buckets()

#     @Endpoint('GET', '/clusters')
#     def clusters(self):
#         return Ganesha.get_ganesha_clusters()
