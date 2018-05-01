class Principal:
    @property
    def id(self):
        return -1
    def is_user(self):
        return False
    def is_group(self):
        return False
    def parse(principal):
        assert(isinstance(principal, str))
        if principal[0] == "u":
            return User.parse(principal)
        if principal[0] == "g":
            return Group.parse(principal)

class User(Principal):
    def __init__(self, uid):
        if not isinstance(uid, int):
            raise TypeError("id {} is not an int, is a {}".format(uid, type(uid)))
        self._uid = uid
    def parse(user):
        assert(user[0] == "u")
        return User(int(user[1:]))
    def __getstate__(self):
        return "u" + str(self._uid)
    def __setstate__(self, state):
        assert(state[0] == "u")
        self._uid = int(state[1:])
    @property
    def id(self):
        return self._uid
    def is_user(self):
        return True
    def __eq__(self, other):
        return isinstance(other, User) and self._uid == other._uid
    def __repr__(self):
        return "<uid={}>".format(self._uid)
    def __hash__(self):
        return hash(("u", self._uid))


class Group(Principal):
    def __init__(self, gid):
        if not isinstance(gid, int):
            raise TypeError("id {} is not an int, is a {}".format(gid, type(gid)))
        self._gid = gid
    def parse(group):
        assert(user[0] == "g")
        return Group(int(group[1:]))
    def __getstate__(self):
        return "g" + str(self._gid)
    def __setstate__(self, state):
        assert(state[0] == "g")
        self._gid = int(state[1:])
    @property
    def id(self):
        return self._gid
    def is_group(self):
        return True
    def __eq__(self, other):
        return isinstance(other, Group) and self._gid == other._gid
    def __repr__(self):
        return "<gid={}>".format(self._gid)
    def __hash__(self):
        return hash(("g", self._gid))

class I:
    def __init__(self, principal, inumber=None):
        if not isinstance(principal, Principal):
            raise TypeError("{} is not a Principal, is a {}".format(principal, type(principal)))
        if inumber is not None and not isinstance(inumber, int):
            raise TypeError("inumber {} is not an int, is a {}".format(inumber, type(inumber)))

        self._p = principal
        self._n = inumber
    def __getstate__(self):
        return (self._p, self._n)
    def __setstate__(self, state):
        self._p = state[0]
        self._n = state[1]
    @property
    def p(self):
        return self._p
    @property
    def n(self):
        return self._n
    def allocate(self, inumber):
        if self._n is not None:
            raise AssertionError("tried to re-allocate allocated I {} with inumber {}".format(self, inumber))
        self._n = inumber
    def allocated(self):
        return self._n is not None
    def __eq__(self, other):
        return isinstance(other, I) and self._p == other._p and self._n == other._n
    def __repr__(self):
        if self.allocated():
            return "({}, {})".format(self._p, self._n)
        return "({}, <unallocated>)".format(self._p)
    def __hash__(self):
        if not self.allocated():
            raise TypeError("cannot hash unallocated i {}".format(self))
        return hash((self._p, self._n))

from collections import defaultdict
from secfs.crypto import sha256_hash
import pickle
class VersionStruct:
    def __init__(self, principal):
        if not isinstance(principal, Principal):
            raise TypeError("{} is not a Principal, is a {}".format(principal, type(principal)))

        self.principal = principal
        self.ihandles = {}                # principals -> i-handles
        self.versions = defaultdict(int)  # principals -> version number
        self.signature = ""               # signature of the version struct

    def __repr__(self):
        return "<VersionStruct v{}, len{}>".format(self.version, len(self.ihandles))

    @property
    def ihandle(self):
        if not self.principal in self.ihandles:
            raise ValueError("VersionStruct {} for principal {} does not have an ihandle yet".format(self, self.principal))
        return self.ihandles[self.principal]

    @property
    def version(self):
        return self.versions[self.principal]

    def set_ihandle(self, principal, ihandle):
        assert(principal.is_group() or principal == self.principal)
        if self.ihandles.get(principal) != ihandle:
            self.ihandles[principal] = ihandle
            return True
        return False

    def increment_version(self, principal):
        self.versions[principal] += 1

    def bytes(self):
        ordered_ihandles = tuple([(str(p), self.ihandles[p]) for p in sorted(self.ihandles.keys())])
        ordered_versions = tuple([(str(p), self.versions[p]) for p in sorted(self.versions.keys())])
        message = (self.principal, ordered_ihandles, ordered_versions)
        return pickle.dumps(message)


# Wrap dictionary in VersionStructList so we can parse principals from RPCs
from collections.abc import Mapping
class VersionStructList(Mapping):
    def __init__(self, _d=None):
        self.d = {}
        if not _d is None:
            assert(isinstance(_d, dict) and "_d is not a dict!")
            for k in _d:
                self[Principal.parse(k)] = _d[k]

    def __repr__(self):
        return self.d.__repr__()

    def __contains__(self, key):
        # if isinstance(key, Principal):
        #    key = str(key)
        return key in self.d

    def __iter__(self):
        for k in self.d:
            yield k

    def __getitem__(self, key):
        # if isinstance(key, Principal):
        #     key = str(key)
        return self.d[key]

    def __setitem__(self, key, value):
        # if isinstance(key, Principal):
        #    key = str(key)
        # if not isinstance(key, str):
        #     raise TypeError("Key {} is not a Principal str, is a {}".format(key, type(key)))
        if not isinstance(key, Principal):
            raise TypeError("Key {} is not a Principal, is a {}".format(key, type(key)))
        if not isinstance(value, VersionStruct):
            raise TypeError("Value {} is not a VersionStruct, is a {}".format(vaule, type(value)))
        assert(value.ihandle)
        # assert(key[0] == "u" or key[0] == "g")

        print("SETTING", key, value, value.ihandle)
        self.d[key] = value

    def __len__(self):
        return len(self.d)
