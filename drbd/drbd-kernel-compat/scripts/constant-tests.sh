#! /bin/bash

[ ! -d drbd/drbd-kernel-compat ] && echo "Must be called from repository root" && exit 1

pushd drbd/drbd-kernel-compat > /dev/null

for f in tests/*.c; do
	define="COMPAT_$(basename -s .c $f | tr a-z A-Z)"
	str=""
	while read line; do
		if [[ $line = \#define* ]]; then
			str+="1 "
		else
			str+="0 "
		fi
	done <<<$(grep --no-filename -P " $define( |$)" cocci_cache/*/compat.h)

	[[ $str != *0* ]] && echo "$define is always set"
	[[ $str != *1* ]] && echo "$define is always unset"
done

popd > /dev/null
