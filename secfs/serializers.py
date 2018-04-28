import Pyro4
from secfs.types import Principal, User, Group, VersionStruct, VersionStructList

def serialize_principal(p):
    assert(p.is_group() ^ p.is_user())
    return ("g" if p.is_group() else "u") + str(p.id)

def deserialize_principal(p):
    assert(p[0] == "u" or p[0] == "g")
    if p[0] == "u":
        return User(int(p[1:]))
    else:
        return Group(int(p[1:]))

def deserialize_version_struct(classname, d):
    assert(d["__class__"] == "VersionStruct")
    vs = VersionStruct(deserialize_principal(d["principal"]))
    for p, ihandle in d["ihandles"]:
        vs.ihandles[deserialize_principal(p)] = ihandle
    for p, version_no in d["version_vector"]:
        vs.version_vector[deserialize_principal(p)] = version_no
    vs.signature = d["signature"]
    return vs

def serialize_version_struct(vs):
    return {
        "__class__": "VersionStruct",
        "principal": serialize_principal(vs.principal),
        "ihandles": [(serialize_principal(p), vs.ihandles[p]) for p in vs.ihandles],
        "version_vector": [(serialize_principal(p), vs.version_vector[p]) for p in vs.version_vector],
        "signature": vs.signature
    }

Pyro4.util.SerializerBase.register_dict_to_class("VersionStruct", deserialize_version_struct)
Pyro4.util.SerializerBase.register_class_to_dict(VersionStruct, serialize_version_struct)
