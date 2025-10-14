#!/bin/bash

autoreconf -fi
./configure
make all check
