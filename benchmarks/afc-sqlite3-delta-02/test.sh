#!/bin/bash
# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

#set -e
set -o pipefail

warn() {
    echo "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

# Install sudo
apt-get install -y sudo

# set parallel value
: "${NPROC_VAL:=$(nproc)}"

# setup temp file to record test output
outdir="/tmp/$(date +"%s.%N" --utc)-cp_tests_sqlite3"
outfile="${outdir}/test.log"
mkdir -p ${outdir} || die "Failed to create test directory: ${outdir}"
rsync --archive --delete ${SRC}/sqlite3 ${outdir} || die "Failed to copy repo to directory: ${outdir}"

# create the user sqliteuser to run the tests (can't be run as root)
LOCAL_USER_ID=1444
LOCAL_USER_GID=1555
NEW_USER="sqliteuser"

sudo mkdir -p /home/${NEW_USER}
sudo groupadd -o -g "${LOCAL_USER_GID}" sqlitegroup 2> /dev/null
sudo useradd -o -m -g "${LOCAL_USER_GID}" -u "${LOCAL_USER_ID}" -d /home/${NEW_USER} ${NEW_USER} -s /bin/bash 2> /dev/null
export HOME=/home/${NEW_USER}
sudo chown -R ${NEW_USER} ${HOME}
sudo chown -R ${LOCAL_USER_ID}:${LOCAL_USER_GID} ${outdir}

# Build
cd ${outdir}/sqlite3/
sudo -u ${NEW_USER} mkdir bld
cd bld
sudo -u ${NEW_USER} ../configure
sudo -u ${NEW_USER} make sqlite3
sudo -u ${NEW_USER} make testfixture
sudo -u ${NEW_USER} bash -c "pushd ${outdir}/sqlite3/bld >/dev/null && ./testfixture ${outdir}/sqlite3/test/testrunner.tcl | tee ${outfile}"


# no logging means internal error
[[ ! -f ${outfile} || ! -s ${outfile} ]] && die "Sqlite3 internal test error code"

# checkout log for failure message from tests
if grep -q "FAILED" ${outfile}; then
    warn "FAILURE: SQLite functional tests failed!"
    exit 1
fi
