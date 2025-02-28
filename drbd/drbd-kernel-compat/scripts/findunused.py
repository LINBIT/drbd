#!/usr/bin/env python3

import os
import json

UNKNOWN, TOGGLED = range(2)
UNDEFINED, DEFINED = 'undefined', 'defined'

defines = {}
for dirpath, _, fnames in os.walk('../cocci_cache'):
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

                if what == 'COMPAT_HAVE_SANE_TEST_ENVIRONMENT' or what == 'COMPAT_HAVE_SANE_TEST_ENVIRONMENT_ALWAYS_FAIL':
                    # these are obviously "always (un)defined", but we don't want to flag them for removal
                    continue

                current = defines.get(what, UNKNOWN)
                if current == UNKNOWN:
                    defines[what] = result
                elif current != result:
                    defines[what] = TOGGLED

prefix = 'compat_'
for k, v in defines.items():
    if v != TOGGLED:
        vers, commit = UNDEFINED, UNDEFINED
        fname = k.lower()
        if fname.startswith(prefix):
            fname = fname[len(prefix):]
        fname += '.c'
        fname = os.path.join('..', 'tests', fname)
        try:
            with open(fname) as fp:
                line = fp.readline().strip()
                if line.startswith('/*') or line.startswith('//'):
                    line = line[2:]
                if line.endswith('*/'):
                    line = line[:-2]
                try:
                    info = json.loads(line)
                    vers = info.get('version', UNDEFINED)
                    commit = info.get('commit', UNDEFINED)
                except:
                    pass
        except IOError:
            print('Could not open file {}'.format(fname))

        print('{} is always {} (v:{}, c:{})'.format(k, v, vers, commit))
