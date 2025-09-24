#!/bin/sh

python3 tr_v2.py > run1.log && \
sc_warts2text foo.warts.gz > run1.txt