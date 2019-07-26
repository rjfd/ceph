# -*- coding: utf-8 -*-
from typing import Type

from . import BodyModel
from .validator import Validator


class Attribute(object):
    def __init__(self, description: str = None, validator: Validator = None,
                 required: bool = True):
        self._description = description
        self._validator = validator
        self._required = required


class String(Attribute):
    pass


class Int(Attribute):
    pass


class Bool(Attribute):
    pass


class ListOf(Attribute):
    def __init__(self, attribute: Attribute, description: str = None,
                 validator: Validator = None, required: bool = True):
        super(ListOf, self).__init__(description, validator, required)
        self._attribute = attribute


class Model(Attribute):
    def __init__(self, model_class: Type[BodyModel], description: str = None,
                 validator: Validator = None, required: bool = True):
        super(Model, self).__init__(description, validator, required)
        self._model_class = model_class
