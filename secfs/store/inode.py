import pickle
import secfs.store.block
import secfs.crypto

class Inode:
    def __init__(self):
        self.size = 0
        self.kind = 0 # 0 is dir, 1 is file
        self.encrypted = 0
        self.ex = False
        self.ctime = 0
        self.mtime = 0
        self.blocks = []

    def load(ihash):
        """
        Loads all meta information about an inode given its ihandle.
        """
        d = secfs.store.block.load(ihash)
        if d == None:
            return None

        n = Inode()
        n.__dict__.update(pickle.loads(d))
        return n

    def read(self, key=None):
        """
        Reads the block content of this inode.
        """
        if self.encrypted and not key:
            # assert False
            # TODO(eforde) Something is reaching this in the tests, look into what it is
            raise PermissionError("No key supplied to read encrypted node {}".format(self))
        blocks = [secfs.store.block.load(b) for b in self.blocks]
        if self.encrypted:
            return b"".join([secfs.crypto.decrypt_sym(key, b) for b in blocks])
        else:
            return b"".join(blocks)

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)
