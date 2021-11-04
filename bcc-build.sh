#!/bin/sh -e
git clone https://github.com/iovisor/bcc.git
mkdir /bcc/build
cd /bcc/build 
cmake ..
make && make install 
cmake -DPYTHON_CMD=python3 ..
cd /bcc/build/src/python/ 
make && make install