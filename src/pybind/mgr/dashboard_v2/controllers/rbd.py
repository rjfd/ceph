# -*- coding: utf-8 -*-
from __future__ import absolute_import

import math

import rbd

from .. import mgr
from ..tools import ApiController, AuthRequired, RESTController, ViewCache, TaskManager


@ApiController('rbd')
@AuthRequired()
class Rbd(RESTController):
    RBD_FEATURES_TO_STR = {
        rbd.RBD_FEATURE_LAYERING: "layering",
        rbd.RBD_FEATURE_STRIPINGV2: "striping",
        rbd.RBD_FEATURE_EXCLUSIVE_LOCK: "exclusive-lock",
        rbd.RBD_FEATURE_OBJECT_MAP: "object-map",
        rbd.RBD_FEATURE_FAST_DIFF: "fast-diff",
        rbd.RBD_FEATURE_DEEP_FLATTEN: "deep-flatten",
        rbd.RBD_FEATURE_JOURNALING: "journaling",
        rbd.RBD_FEATURE_DATA_POOL: "data-pool",
        rbd.RBD_FEATURE_OPERATIONS: "operations",
    }
    RBD_STR_TO_FEATURES = dict((v, k) for k, v in RBD_FEATURES_TO_STR.items())

    @classmethod
    def _bitmask_to_features_string(cls, features):
        """
        Formats the bitmask as a list of features string:

        >>> Rbd._bitmask_to_features_string(45)
        'deep-flatten, exclusive-lock, layering, object-map'
        """
        names = [val for key, val in cls.RBD_FEATURES_TO_STR.items()
                 if key & features == key]
        return ', '.join(sorted(names))

    @classmethod
    def _features_string_to_bitmask(cls, features):
        """
        Transforms a list of features strings into a bitmask:

        >>> Rbd._features_string_to_bitmask(['deep-flatten', 'exclusive-lock', 'layering', \
                                             'object-map'])
        45
        """
        bitmask = 0
        for feature in features:
            bitmask = bitmask | cls.RBD_STR_TO_FEATURES[feature]
        return bitmask

    @ViewCache()
    def _rbd_list(self, pool_name):
        ioctx = mgr.rados.open_ioctx(pool_name)
        rbd_inst = rbd.RBD()
        names = rbd_inst.list(ioctx)
        result = []
        for name in names:
            i = rbd.Image(ioctx, name)
            stat = i.stat()
            stat['name'] = name
            features = i.features()
            stat['features'] = features
            stat['features_name'] = self._bitmask_to_features_string(features)

            try:
                parent_info = i.parent_info()
                parent = "{}@{}".format(parent_info[0], parent_info[1])
                if parent_info[0] != pool_name:
                    parent = "{}/{}".format(parent_info[0], parent)
                stat['parent'] = parent
            except rbd.ImageNotFound:
                pass
            result.append(stat)
        return result

    def get(self, pool_name):
        # pylint: disable=unbalanced-tuple-unpacking
        status, value = self._rbd_list(pool_name)
        if status == ViewCache.VALUE_EXCEPTION:
            raise value
        return {'status': status, 'value': value}

    @classmethod
    def _create_image(cls, data):
        pool_name = data['pool_name']
        ioctx = mgr.rados.open_ioctx(pool_name)
        rbd_inst = rbd.RBD()
        name = data['image_name']
        size = data['size']
        order = int(math.log(data['obj_size'], 2))
        old_format = False
        features = cls._features_string_to_bitmask(data['features'])
        stripe_unit = data['stripe_unit']
        stripe_count = data['stripe_count']
        data_pool = data['data_pool']
        try:
            rbd_inst.create(ioctx, name, size, order, old_format, features,
                            stripe_unit, stripe_count, data_pool)
        except rbd.OSError as ex:
            return {'success': False, 'message': str(ex), 'errno': ex.errno}
        return {'success': True}

    @classmethod
    def _remove_image(cls, pool_name, image_name):
        ioctx = mgr.rados.open_ioctx(pool_name)
        rbd_inst = rbd.RBD()
        try:
            rbd_inst.remove(ioctx, image_name)
        except rbd.OSError as ex:
            return {'success': False, 'message': str(ex), 'errno': ex.errno}
        return {'success': True}

    def create(self, data):
        status, val = TaskManager.run("rbd/create",
                                      {'image_name': data['image_name'],
                                       'pool_name': data['pool_name']},
                                      self._create_image, data)
        return {'status': status, 'value': val}

    def delete(self, pool_name, image_name):
        status, val = TaskManager.run("rbd/remove",
                                      {'image_name': image_name,
                                       'pool_name': pool_name},
                                      self._remove_image,
                                      pool_name, image_name)
        return {'status': status, 'value': val}
