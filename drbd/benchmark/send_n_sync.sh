#!/bin/sh

dd if=/dev/zero of=/dev/nb0 bs=1024 count=$1 2> /dev/null
sync
