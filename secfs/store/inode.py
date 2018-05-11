import pickle
import secfs.store.block
import secfs.crypto
from secfs.types import I

class Inode:

    ihash_encrypted = {}  #ihash -> encrypted(bool)

    def __init__(self):
        self.size = 0
        self.kind = 0 # 0 is dir, 1 is file
        self.encrypted = 0
        self.ex = False
        self.ctime = 0
        self.mtime = 0
        self.blocks = []
        # TODO(eforde): perhaps take in key of current user when inodes are initialized
        # then can just try to decrypt encrypted things with that key

    def load(ihash, key=None):
        """
        Loads all meta information about an inode given its ihandle.
        """
        if Inode.ihash_encrypted[ihash] and not key:
            raise PermissionError("No key supplied to load encrypted inode {}".format(ihash))
        d = secfs.store.block.load(ihash, key if Inode.ihash_encrypted[ihash] else None)  # inodes shouldn't be encrypted
        if d == None:
            return None

        n = Inode()
        n.__dict__.update(pickle.loads(d))
        return n

    def save(self, key=None):
        bts = self.bytes()
        if self.encrypted and not key:
            raise PermissionError("No key supplied to save encrypted inode {}".format(self))
        ihash = secfs.store.block.store(bts,key if self.encrypted else None)
        Inode.ihash_encrypted[ihash] = self.encrypted
        return ihash
        

    def read(self, key=None):
        """
        Reads the block content of this inode.
        """
        if self.encrypted and not key:
            # assert False
            # TODO(eforde) Something is reaching this in the tests, look into what it is
            raise PermissionError("No key supplied to read encrypted node {}".format(self))
        if not self.encrypted:  # just don't pass in the key if this isn't encrypted
            key = None
        blocks = [secfs.store.block.load(b, key) for b in self.blocks]
        return b"".join(blocks)

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)
