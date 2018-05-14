#!/bin/sh
base=$(dirname "$0")
cd "$base" || exit 1

# we're going to need sudo
sudo date > /dev/null

# kill previous clients, servers, and tests
./stop.sh 2>/dev/null
sudo umount secfs-test.*/mnt* 2>/dev/null
rm -rf secfs-test.* 2>/dev/null

# in case students have changed it
umask 0022

# Build and enable
# shellcheck disable=SC1091
. venv/bin/activate
pip3 install --upgrade -e . > pip.log

# shellcheck source=test-lib.sh
. "$base/test-lib.sh"

# start a clean server for testing
info "starting server"
env PYTHONUNBUFFERED=1 venv/bin/secfs-server "$uxsock" > server.log 2> server.err &
server=$!

# wait for server to start and announce its URI
sync
while ! grep -P "^uri =" server.log > /dev/null; do
	sleep .2
done
uri=$(grep "uri = PYRO:secfs" server.log | awk '{print $3}')

# start primary client and connect it to the server
info "connecting to server at %s" "$uri"
sudo rm -f root.pub user-*-key.pem
client


section "rm sudo files"
# root rm file
expect "echo x | sudo tee root-file" "sudo cat root-file" '^x$' || fail "couldn't read back root created file"
expect "echo x | sudo tee -a root-file" "sudo cat root-file" '^x\nx$' || fail "couldn't read back root appended file"
cant "delete root file using user" "rm root-file"
expect "sudo rm root-file" "sudo ls" '^$' || fail "couldn't remove file"

section "rm -r sudo dirs"
# root single-user rm empty dir
expect "sudo mkdir root-only" '^$' || fail "couldn't make root directory"
cant "delete root dir using user" "rm -r root-only"
expect "sudo rm -r root-only" '^$' || fail "couldn't remove root directory"
# recursive rm
expect "sudo mkdir root-only" "echo x | sudo tee root-only/root-file" "sudo rm -r root-only" '^$' || fail "couldn't recursively delete populated directory as root"

section "rm -r shared dir"
# shared operations
expect "sudo sh -c 'umask 0200; sg users \"mkdir shared\"'" '^$' || fail "couldn't create group-owned directory"
user=$(id -un)
expect "echo b | tee shared/user-file" "cat shared/user-file" '^b$' || fail "couldn't create user file in shared directory"
expect "mkdir shared/user-only" '^$' || fail "couldn't make user directory in shared dir"
cant "have root delete folder with unowned contents" "sudo rm -r shared/"

# Only use this test case if you assume you can delete a file you can write to 
#   in a directory that you cannot write to
# expect "rm -r shared/" "sudo ls"

cleanup

info "all tests done (passed %d/%d -- %.1f%%); cleaning up\n" "$passed" "$tests" "$(echo "100*$passed/$tests" | bc -l)"
