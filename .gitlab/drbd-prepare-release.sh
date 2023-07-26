#!/bin/bash

# Replace the drbd version number in all necessary places
#
# Example:
# version=9.1.15+ptf.16.g0a58e61fcd09
# PATH=~/work/projects/build-helpers/build-helpers:"$PATH" ./.gitlab/drbd-prepare-release.sh "$version" 1 "$version"
#
# Example of a real release:
# version=9.1.16
# PATH=~/work/projects/build-helpers/build-helpers:"$PATH" DRBD_SOURCE_ONLINE=yes ./.gitlab/drbd-prepare-release.sh "$version" 1 "$version"

version="$1"
release="$2"
rel_version="$3"

DIR="$(dirname "$(readlink -f "$0")")"

dummy-release.sh drbd "$version" "$release" drbd-kernel.spec --source-online ${DRBD_SOURCE_ONLINE:-no}

sed -re "s/(#define REL_VERSION) .*/\1 \"$rel_version\"/g" drbd/linux/drbd_config.h > drbd/linux/drbd_config.h.tmp
mv drbd/linux/drbd_config.h{.tmp,}

for i in 7 8 9; do
	sed -re "s/(ENV DRBD_VERSION) .*/\1 $rel_version/g" docker/Dockerfile.rhel${i} > docker/Dockerfile.rhel${i}.tmp
	mv docker/Dockerfile.rhel${i}{.tmp,}
done

awk -f "$DIR/changelog.awk" -v REL_VERSION="$rel_version" ChangeLog > ChangeLog.tmp
mv ChangeLog{.tmp,}
