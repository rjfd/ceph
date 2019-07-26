# -*- coding: utf-8 -*-

class Validator(object):
    pass


class Regex(Validator):
    pass


class Length(Validator):
    def __init__(self, max_len: int = None, min_len: int = None):
        self._max = max_len
        self._min = min_len

class NotEmpty(Validator):
    pass


class IPAddress(Validator):
    pass


class Enum(Validator):
    def __init__(self, *args):
        self._options = args


class Gt(Validator):
    def __init__(self, value):
        self._value = value
