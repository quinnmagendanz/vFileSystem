# This file contains all code handling the resolution and modification of i
# mappings. This includes group handle indirection and VSL validation, so the
# file is somewhat hairy.
# NOTE: an ihandle is the hash of a principal's itable, which holds that
# principal's mapping from inumbers (the second part of an i) to inode hashes.



import pickle
import secfs.store
import secfs.crypto
import secfs.fs
from secfs.types import I, Principal, User, Group, VersionStruct, VersionStructList

vsl = VersionStructList()  # User -> VersionStruct
itables = {}  # Principal -> itable
last_vs_bytes = None

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
    print("---PRE", user)
    update_vsl()
    assert(user.is_user())
    global active_user
    active_user = user

    # refresh usermap and groupmap
    if refresh != None:
        refresh()

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
    global last_vs_bytes
    updated_vs = update_vs(active_user)
    if updated_vs is not None:
        print("Commiting vs {} for".format(updated_vs), active_user)
        server.commit(active_user, updated_vs)
        last_vs_bytes = updated_vs.bytes()

    print("---POST\n")
 
def update_vs(user):
    if not user in itables:
        # was a read only operation for a new user, nothing to commit
        print("No itable for {}, not committing vs\n".format(user))
        return None

    vs = vsl.get(user)
    if vs is None:
        print("ALERT!!! VS is none for user", user)
        vs = create_new_vs(user)
        vsl[user] = vs

    # Update ihandles and version numbers for this vs
    for p in itables:
        itable = itables[p]
        if itable.updated:
            # make sure updated ihandles were allowed to be updated
            assert((p.is_user() and p == user) or
                    user in secfs.fs.groupmap[p])
            if vs.set_ihandle(p, itable.save()):
                vs.set_version(p, itable.version + 1)
        elif vs.versions[p] < itable.version:
            # make sure all version numbers are up-to-date
            vs.versions[p] = itables[p].version
            if p in vs.ihandles:
                vs.set_ihandle(p, itable.ihandle)

    # Check if the versions structures have a total ordering
    for u1 in vsl:
        for u2 in vsl:
            vs1 = vsl[u1]
            vs2 = vsl[u2]
            gt = False
            lt = False
            for u3 in vsl:
                gt = gt or vs1.versions.get(u3, 0) > vs2.versions.get(u3, 0)
                lt = lt or vs1.versions.get(u3, 0) < vs2.versions.get(u3, 0)
            if gt and lt:
                print("VSL IS NOT CONSISTENT")
                print([user, vs.versions], [u1, vs1.versions], [u2, vs2.versions])
                raise ValueError("Cannot Create a total ordering of Version Numbers")

    private_key = secfs.crypto.keys[user]
    data = vs.bytes()
    vs.signature = secfs.crypto.sign(private_key, data)
    return vs

def update_vsl():
    global server
    global vsl
    global itables
    global last_vs_bytes
    vsl = VersionStructList(server.get_vsl())
    itables = {}
    # populate itables
    for user in vsl:
        vs = vsl[user]
        if user in secfs.fs.usermap:
            public_key = secfs.fs.usermap[user]
        else:
            print("User {} not in usermap yet, probably during init... {}".format(user, secfs.fs.usermap))
            public_key = secfs.crypto.keys[user].public_key()

        assert(secfs.crypto.verify(public_key, vs.signature, vs.bytes()))
        for principal in vs.ihandles:
            ihandle = vs.ihandles[principal]
            version = vs.versions[principal]
            print("Principal {} from {}'s VS has version {} ihandle: {}".format(principal, user, version, ihandle))
            if ((principal in itables and itables[principal].version < version) or
                principal not in itables):
                itables[principal] = Itable.load(ihandle, version, principal)
            elif itables[principal].version == version:
                assert(itables[principal].ihandle == ihandle)
    print("DOWNLOADED VSL", vsl, type(vsl))
    print("    with itables", itables)
    # not sure how to assert this since another client can act on behalf of same user
    # assert((last_vs_bytes is None or vsl.contains_old_vs(last_vs_bytes)) and "VSL should contain last VS")

def create_new_vs(principal):
    vs = VersionStruct(principal)
    global itables
    for p in itables:
        # create the version vector, initialized with each principal's version
        vs.versions[p] = itables[p].version
    vs.set_ihandle(principal, itables[principal].ihandle)
    vs.set_version(principal, 1)
    return vs

class Itable:
    """
    An itable holds a particular principal's mappings from inumber (the second
    element in an i tuple) to an inode hash for users, and to a user's i for
    groups.
    """
    def __init__(self):
        self.version = 0
        self.ihandle = None
        self.updated = False
        self.keys = {}  # principals => encrypted key
        self.mapping = {}  # inumber => ihash

    def create(owner):
        itable = Itable()
        itable._generate_private_keys(owner)
        return itable

    def load(ihandle, version, owner):
        itable = Itable()
        itable.ihandle = ihandle
        itable.version = version
        b = secfs.store.block.load(ihandle, None) # itable should never be encrypted
        if b == None:
            # TODO(eforde): this may happen if we start deleting unused ihandles on the server?
            raise KeyError("No block for ihandle {}".format(_ihandle))
        rep = pickle.loads(b)
        for (inumber, ihash) in rep[0]:
            itable.mapping[inumber] = ihash
        for (principal, encrypted_key) in rep[1]:
            itable.keys[Principal.parse(principal)] = encrypted_key

        if not len(itable.keys):
            # This itable was probably made during init when usermap wasn't populated
            itable._generate_private_keys(owner)
        return itable

    def _generate_private_keys(self, owner):
        if not len(secfs.fs.usermap):  # Hack to not generate private keys during init
            print("No usermap - can't generate keys for itable owned by {}".format(owner))
            return

        print("Generating keys for itable owned by {}".format(owner))
        private_key = secfs.crypto.generate_sym_key()  # used for encrypted files for the owner
        
        if owner.is_user():
            print("encrypting key {} for user {}".format(private_key, owner))
            # Encrypt this itable's private key with the owner's public key
            self.keys[owner] = secfs.crypto.encrypt(secfs.fs.usermap[owner], private_key)
        elif owner.is_group():
            # Encrypt this itable's private key with each member's public key
            for user in secfs.fs.groupmap[owner]:
                print("encrypting key {} for user {} in group {}".format(private_key, user, owner))
                self.keys[user] = secfs.crypto.encrypt(secfs.fs.usermap[user], private_key)
        # Mark the table as updated so we upload the itable owners' keys to the server
        # We throw away the private key here, so only owners can decrypt their encrypted key
        self.updated = True
        # TODO(eforde): deal with users being added to the group later?

    def __repr__(self):
        return "<Itable v{} {}>".format(self.version, self.ihandle)

    def bytes(self):
        rep = (
            [(i, self.mapping[i]) for i in sorted(self.mapping.keys())],
            [(p.__getstate__(), self.keys[p]) for p in sorted(self.keys.keys(), key=lambda k: str(k))]
            # TODO(eforde): why do i have to use getstate here
        )
        return pickle.dumps(rep)

    def save(self):
        new_ihandle = secfs.store.block.store(self.bytes(), None) # itables not encrypted
        self.ihandle = new_ihandle
        self.updated = True
        return new_ihandle

    def get_key(self, user):
        """
        Gets the private key for the user if they are an owner of the itable
        """
        if not user in self.keys:
            return None
        private_key = secfs.crypto.keys[user]
        return secfs.crypto.decrypt(private_key, self.keys[user])

def get_itable_key(table_principal, user):
    if not isinstance(table_principal, Principal):
        raise TypeError("{} is not a Principal, is a {}".format(table_principal, type(table_principal)))
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))
    global itables
    assert(table_principal in itables)
    key = itables[table_principal].get_key(user)
    if key is None:
        print("user {} asked for {}'s key but does not own itable".format(user, table_principal))
    return key

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
        if not (i.p.is_group() and mod_as.is_user()): # if not for self, then must be for group
            raise PermissionError("cannot modmap for {} as {}".format(i.p, mod_as)) 

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
        t = Itable.create(i.p)
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

def remove(i):
    """
    Removes the given i from its itable and its mapping
    """
    assert(i.p in itables)
    t = itables[i.p]
    assert(i.n in t.mapping)
    print("Removing child i:{} from table mapping".format(i))
    del t.mapping[i.n]
    t.save()
    
