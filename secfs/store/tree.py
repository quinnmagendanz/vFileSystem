# This file provides functionality for manipulating directories in SecFS.

import pickle
import secfs.fs
import secfs.crypto
import secfs.tables
import secfs.store.block
from secfs.store.inode import Inode
from secfs.types import I, Principal, User, Group

def find_under(dir_i, name, read_as=None):
    """
    Attempts to find the i of the file or directory with the given name under
    the directory at i.
    """
    if not isinstance(dir_i, I):
        raise TypeError("{} is not an I, is a {}".format(dir_i, type(dir_i)))
    
    key = secfs.tables.get_itable_key(dir_i.p, read_as) if read_as else None
    dr = Directory(dir_i, key)
    for f in dr.children:
        if f[0] == name:
            return f[1]
    return None

class Directory:
    """
    A Directory is used to marshal and unmarshal the contents of directory
    inodes. To load a directory, an i must be given.
    """
    def __init__(self, i, key):
        if not isinstance(i, I):
            raise TypeError("{} is not an I, is a {}".format(i, type(i)))

        self.inode = None
        self.children = []

        self.inode = secfs.fs.get_inode(i)
        if self.inode.kind != 0:
            raise TypeError("inode with ihash {} is not a directory".format(secfs.tables.resolve(i)))
        self.encrypted = self.inode.encrypted

        cnt = self.inode.read(key)
        if len(cnt) != 0:
            self.children = pickle.loads(cnt)

    def bytes(self):
        return pickle.dumps(self.children)

def add(dir_i, name, i, key=None):
    """
    Updates the directory's inode contents to include an entry for i under the
    given name.
    """
    if not isinstance(dir_i, I):
        raise TypeError("{} is not an I, is a {}".format(dir_i, type(dir_i)))
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    dr = Directory(dir_i, key)
    if not dr.encrypted:
        key = None
    for f in dr.children:
        if f[0] == name:
            raise KeyError("asked to add i {} to dir {} under name {}, but name already exists".format(i, dir_i, name))

    dr.children.append((name, i))

    new_dhash = secfs.store.block.store(dr.bytes(), key)
    dr.inode.blocks = [new_dhash]
    new_ihash = secfs.store.block.store(dr.inode.bytes(), None) # inodes not encrypted
    return new_ihash

def remove(dir_i, name, key=None):
    """
    Removes name from the directory
    """
    if not isinstance(dir_i, I):
        raise TypeError("{} is not an I, is a {}".format(dir_i, type(dir_i)))

    dr = Directory(dir_i, key)
    if not dr.encrypted:
        key = None

    for f in range(len(dr.children)):
        if dr.children[f][0] == name:
             print("Removed child {} from dir{} children".format(name, dir_i))
             del dr.children[f]
             break
    new_dhash = secfs.store.block.store(dr.bytes(), key)
    dr.inode.blocks = [new_dhash]
    new_ihash = secfs.store.block.store(dr.inode.bytes(), None) # inodes not encrypted
 
    return new_ihash
