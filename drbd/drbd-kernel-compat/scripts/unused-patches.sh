#! /bin/sh

# Prints all cocci patches that are never used in the current cocci_cache.
# Implies that `make compat` has previously been run to generate the applied_cocci_files.txt files

for f in cocci/*; do
	patch="$(basename -s .cocci $f)"
	grep -qFx $patch cocci_cache/*/applied_cocci_files.txt || echo "$f"
done
