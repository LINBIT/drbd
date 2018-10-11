#!/usr/bin/env python

import os

UNKNOWN, TOGGLED = range(2)
UNDEFINED, DEFINED = 'undefined', 'defined'

defines = {}
for dirpath, _, fnames in os.walk('./all'):
    for compat in fnames:
        if not compat.startswith("compat.h"):
            continue
        with open(os.path.join(dirpath, compat)) as f:
            lines = f.readlines()
            for l in lines:
                sp = l.strip().split()

                what, result = '', ''
                if sp[0] == '/*' and sp[1] == '#undef':
                    what, result = sp[2], UNDEFINED
                elif sp[0] == '#define':
                    what, result = sp[1], DEFINED
                else:
                    continue

                current = defines.get(what, UNKNOWN)
                if current == UNKNOWN:
                    defines[what] = result
                elif current != result:
                    defines[what] = TOGGLED

for k, v in defines.items():
    if v != TOGGLED:
        print('{} is always {}'.format(k, v))
