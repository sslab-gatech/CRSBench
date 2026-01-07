#!/bin/bash
set -ex

# Install dependencies (quick if already installed)
apt install -y libxml2-dev
pip install pytest pytest-xdist

cd "$SRC/wireshark"

# Only run cmake if not already configured
# Since $SRC is separate between build.sh and test.sh, in-source build is fine
if [ ! -f Makefile ]; then
    cmake -DBUILD_wireshark=NO -DBUILD_stratoshark=NO -DBUILD_sharkd=NO \
          -DVCSVERSION_OVERRIDE="Git v3.1.0 packaged as 3.1.0-1" .
fi

make -j$(nproc)

# Run tests
pytest --skip-missing-programs all -k 'not clopts' --disable-capture --ignore test/suite_capture.py
