# This file contains all code handling the resolution and modification of i
# mappings. This includes group handle indirection and VSL validation, so the
# file is somewhat hairy.
# NOTE: an ihandle is the hash of a principal's itable, which holds that
# principal's mapping from inumbers (the second part of an i) to inode hashes.

from collections import defaultdict

import pickle
import secfs.store
import secfs.fs
from secfs.types import I, Principal, User, Group, VersionStruct, VersionStructList

vsl = VersionStructList()  # User -> VersionStruct
itables = {}  # Principal -> itable

# a server connection handle is passed to us at mount time by secfs-fuse
server = None
active_user = None
def register(_server):
    global server
    server = _server

def pre(refresh, user):
    """
    Called before all user file system operations, right after we have obtained
    an exclusive server lock.
    """
    update_vsl()

    # refresh usermap and groupmap
    if refresh != None:
        refresh()
    global active_user  # TODO(eforde): ewewewewewew
    active_user = user

def post(push_vs):
    if not push_vs:
        # when creating a root, we should not push a VS (yet)
        # you will probably want to leave this here and
        # put your post() code instead of "pass" below.
        return
    global server
    global active_user
    global vsl
    global itables
    if not active_user in itables:
        # was a read only operation for a new user, nothing to commit
        print("No itable for {}, not committing vs\n".format(active_user))
        return

    vs = vsl.get(active_user)
    if vs is None:
        print("ALERT!!! VS is none for user", active_user)
        for p in itables:
            print(active_user, p, type(active_user), type(p))
        vs = create_new_vs(active_user)
        vsl[active_user] = vs

    # Update ihandles for this vs
    for p in itables:
        itable = itables[p]
        if itable.updated:
            # make sure updated ihandles were allowed to be updated
            assert((p.is_user() and p == active_user) or
                    active_user in secfs.fs.groupmap[p])
            if vs.set_ihandle(p, itable.ihandle):
                vs.increment_version(p)
    # TODO(eforde): sign vs
    print("Commiting vs {} for".format(vs), active_user)
    server.commit(active_user, vs)
    print("")

def update_vsl():
    global server
    global vsl
    global itables
    vsl = VersionStructList(server.get_vsl())
    print("DOWNLOADED VSL", vsl, type(vsl))
    itables = {}
    # populate itables
    for user in vsl:
        for principal in vsl[user].ihandles:
            ihandle = vsl[user].ihandles[principal]
            version = vsl[user].versions[principal]
            if ((principal in itables and itables[principal].version < version) or
                principal not in itables):
                itables[principal] = Itable(ihandle, version)
            elif itables[principal].version == version:
                assert(itables[principal].ihandle == ihandle)

    print("    with itables", itables)

def create_new_vs(principal):
    vs = VersionStruct(principal)
    global itables
    for p in itables:
        # create the version vector, initialized with each principal's version
        vs.versions[p] = itables[p].version
    vs.set_ihandle(principal, itables[principal].ihandle)
    vs.increment_version(principal)
    return vs

class Itable:
    """
    An itable holds a particular principal's mappings from inumber (the second
    element in an i tuple) to an inode hash for users, and to a user's i for
    groups.
    """
    def __init__(self, _ihandle=None, _version=0):
        self.version = _version
        self.ihandle = _ihandle
        self.updated = False
        self.mapping = {} # TODO(eforde): could be list?
        if not _ihandle:
            return
        b = secfs.store.block.load(_ihandle)
        if b == None:
            # TODO(eforde): this may happen if we start deleting unused ihandles on the server?
            raise KeyError("No block for ihandle {}".format(_ihandle))
        for (inumber, ihash) in pickle.loads(b):
            self.mapping[inumber] = ihash

    def __repr__(self):
        return "<Itable v{} {}>".format(self.version, self.ihandle)

    def bytes(self):
        return pickle.dumps([(i, self.mapping[i]) for i in sorted(self.mapping.keys())])

    def save(self):
        new_ihandle = secfs.store.block.store(self.bytes())
        self.ihandle = new_ihandle
        self.updated = True
        return new_ihandle


def resolve(i, resolve_groups = True):
    """
    Resolve the given i into an inode hash. If resolve_groups is not set, group
    is will only be resolved to their user i, but not further.

    In particular, for some i = (principal, inumber), we first find the itable
    for the principal, and then find the inumber-th element of that table. If
    the principal was a user, we return the value of that element. If not, we
    have a group i, which we resolve again to get the ihash set by the last
    user to write the group i.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    principal = i.p

    if not isinstance(principal, Principal):
        raise TypeError("{} is not a Principal, is a {}".format(principal, type(principal)))

    if not i.allocated():
        # someone is trying to look up an i that has not yet been allocated
        return None

    global itables
    if principal not in itables:
        # User does not yet have an itable
        return None 

    t = itables[principal]
    if i.n not in t.mapping:
        raise LookupError("principal {} does not have i {}".format(principal, i))

    # santity checks
    if principal.is_group() and not isinstance(t.mapping[i.n], I):
        raise TypeError("looking up group i, but did not get indirection ihash")
    if principal.is_user() and isinstance(t.mapping[i.n], I):
        raise TypeError("looking up user i, but got indirection ihash")

    if isinstance(t.mapping[i.n], I) and resolve_groups:
        # we're looking up a group i
        # follow the indirection
        return resolve(t.mapping[i.n])

    return t.mapping[i.n]

def modmap(mod_as, i, ihash):
    """
    Changes or allocates i so it points to ihash.

    If i.allocated() is false (i.e. the I was created without an i-number), a
    new i-number will be allocated for the principal i.p. This function is
    complicated by the fact that i might be a group i, in which case we need
    to:

      1. Allocate an i as mod_as
      2. Allocate/change the group i to point to the new i above

    modmap returns the mapped i, with i.n filled in if the passed i was no
    allocated.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(mod_as, User):
        raise TypeError("{} is not a User, is a {}".format(mod_as, type(mod_as)))

    assert mod_as.is_user() # only real users can mod

    if mod_as != i.p:
        print("trying to mod object for {} through {}".format(i.p, mod_as))
        assert i.p.is_group() and mod_as.is_user() # if not for self, then must be for group

        real_i = resolve(i, False)
        if isinstance(real_i, I) and real_i.p == mod_as:
            # We updated the file most recently, so we can just update our i.
            # No need to change the group i at all.
            # This is an optimization.
            i = real_i
        elif isinstance(real_i, I) or real_i == None:
            if isinstance(ihash, I):
                # Caller has done the work for us, so we just need to link up
                # the group entry.
                print("mapping", i, "to", ihash, "which again points to", resolve(ihash))
            else:
                # Allocate a new entry for mod_as, and continue as though ihash
                # was that new i.
                # XXX: kind of unnecessary to send two VS for this
                _ihash = ihash
                ihash = modmap(mod_as, I(mod_as), ihash)
                print("mapping", i, "to", ihash, "which again points to", _ihash)
        else:
            # This is not a group i!
            # User is trying to overwrite something they don't own!
            raise PermissionError("illegal modmap; tried to mod i {0} as {1}".format(i, mod_as))

    # find (or create) the principal's itable
    global itables
    vs = None
    t = None
    if i.p not in itables:
        if i.allocated():
            # this was unexpected;
            # user did not have an itable, but an inumber was given
            raise ReferenceError("itable not available")
        t = Itable()
        itables[i.p] = t
        print("no current list for principal", i.p, "; creating empty table", t.mapping)
    else:
        t = itables[i.p]

    # look up (or allocate) the inumber for the i we want to modify
    if not i.allocated():
        inumber = 0
        while inumber in t.mapping:
            inumber += 1
        i.allocate(inumber)
    else:
        if i.n not in t.mapping:
            raise IndexError("invalid inumber")

    # modify the entry, and store back the updated itable
    if i.p.is_group():
        print("mapping", i.n, "for group", i.p, "into", t.mapping)

    t.mapping[i.n] = ihash # for groups, ihash is an i
    t.save()
    return i
