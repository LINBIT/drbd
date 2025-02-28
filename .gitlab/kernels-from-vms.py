#!/usr/bin/env python3

import os
import sys

import toml

# kernels-from-vms.py
# Extract kernel versions to be built from a vmshed vms.toml file supplied on stdin
# Respects the EXCLUDE_BASE_IMAGES environment variable to exclude specific base images

exclude_base_images = os.getenv("EXCLUDE_BASE_IMAGES", "").split(",")

vms = toml.load(sys.stdin)
for vm in vms["vms"]:
    meta = vm["metadata"]
    if vm["base_image"] in exclude_base_images or "BuildDistribution" not in meta:
        continue
    print(f"{meta['BuildDistribution']} {meta['BuildKernel']}")
