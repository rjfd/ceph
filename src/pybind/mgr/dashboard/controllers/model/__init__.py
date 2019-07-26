# -*- coding: utf-8 -*-

from .validator import Validator


class _Model(object):
    pass


class PathModel(_Model):  # maybe it's too much, otoh it would allow automatic validation
    pass


class HeaderModel(_Model):
    pass


class QueryModel(_Model):
    pass


class BodyModel(_Model):
    pass
