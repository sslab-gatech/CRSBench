#!/bin/bash
pushd $SRC/cp-user-stress-test-src && make && make install DESTDIR=$OUT && popd
