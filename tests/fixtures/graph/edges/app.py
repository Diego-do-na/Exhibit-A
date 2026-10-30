import os

import pkg.helpers
import pkg.helpers as hh
from pkg import exported_helper
from pkg import models as m
from pkg.models import Service, Store


def absolute():
    return pkg.helpers.helper()


def aliased():
    return hh.other()


def reexported():
    return exported_helper()


def ctor_then_method():
    store = Store("x")
    return store.load()


def chained():
    return Store("y").load()


def module_attr_class():
    return m.Store("z")


def annotated(store: Store):
    return store.save()


def service():
    return Service().run()


def callback():
    return run(helper_cb)


def helper_cb():
    return "called back"


def run(fn):
    return fn()


def unknown_receiver(obj):
    return obj.anything()


def dynamic(name):
    return getattr(os, name)()


def external(path):
    return os.path.join(path, "x")


def shadowed(open):
    return open("not the builtin")
