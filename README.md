# DRBD

DRBD, developed by [LINBIT](https://www.linbit.com), provides networked RAID 1 functionality for GNU/Linux.
It is designed for high availability clusters and software defined storage.
DRBD keeps disks on multiple nodes synchronized using TCP/IP or RDMA and makes the data available as a block device.
This results in RAID 1 but without the use of uncommon hardware such as shared SCSI buses or Fibre Channel.

This repository contains the Linux kernel code for DRBD version 9 and above.

# Using DRBD
Please read the user-guide provided at [docs.linbit.com](https://docs.linbit.com).

# Support
For further products and professional support, please
[contact](http://links.linbit.com/support) us.

# Contributing
Development is coordinated via [mailing lists](http://lists.linbit.com). Currently, we do not intend to use
github issue tracking/github PRs.

## Style checking
Since the code of this module is intended for the Linux kernel tree, we apply
the corresponding code style checks. You should ensure that your contributions
pass these checks. This can be easily achieved by installing a pre-commit hook,
as follows:

```
curl -L https://github.com/torvalds/linux/raw/master/scripts/checkpatch.pl | sudo tee /usr/local/bin/checkpatch.pl | wc
sudo chmod +x /usr/local/bin/checkpatch.pl
curl -L https://github.com/torvalds/linux/raw/master/scripts/spelling.txt | sudo tee /usr/local/bin/spelling.txt | wc
sudo echo > /usr/local/bin/const_structs.checkpatch
cp misc/pre-commit .git/hooks/
```

# Building DRBD

Since version 9.0.20, DRBD has been using a kernel backwards compatibility system
based on [Coccinelle](https://github.com/coccinelle/coccinelle) semantic patches.
While this has many advantages, it also makes it a little harder for "casual"
developers to build DRBD from the git sources. The problem is that we require a
very recent version of `spatch` (at least 1.0.8 at time of writing), and most
distributions only have relatively old versions in their repositories.

## From git

For users wishing to build DRBD from its git sources, here are a few options:
1. Use a recent kernel. When building against a recent(ish) upstream kernel,
   chances are you won't even have to use any of the compat features, which
   means you won't require compatibility patches and in turn don't need spatch
   installed.
2. On Ubuntu 18.04 and newer, use a recent spatch version from the
   [Coccinelle PPA](https://launchpad.net/~npalix/+archive/ubuntu/coccinelle).
   This provides (at time of writing) version 1.0.8, which is recent enough to
   build DRBD.
3. Build and install spatch from source. This will also give you a version that
   is recent enough to build DRBD.

## From a release tarball

For use cases where it is appropriate to just build DRBD from a release tarball,
here are some options:
1. Use a distribution kernel and rely on the shipped "compat patch cache". We
   pre-generate compatibility patches for a list of commonly used distribution
   kernels and ship them with every release tarball. If your kernel matches one
   of those in the cache, you won't need spatch because the cached patch will be
   applied directly.
2. For all other kernels, you can use LINBIT's "spatch as a service" online
   service, which transparently and automatically generates compatibility
   patches based on your kernels feature set.
3. If you are using an exotic kernel and you do not have internet access or
   otherwise can't or don't want to use "spatch as a service", you will have to
   install a recent version of coccinelle (see above).

For a release tarball, these options should be handled transparently for the
user. In other words, if you download a tarball and type "make", it should work
in next to all cases.

## Provided kernel compatibility / compatibility after a release

With the usual exceptions compat work is usually done relatively late in the
release cycle. When we then provide a new release tarball one can usually
expect that this version compiles without compat for the latest Linux upstream
kernel at the time. This is because our code is then in a shape that it does not
require any compat for latest upstream. One can also expect that we ship
pre-generated compat patches for the distributions (and distribution kernels)
we care about. So what are the kernels we care about? These are the kernels
and distributions our customers use (at the point writing these lines we build
for 140 kernels). These include the usual suspects such as Debian, Ubuntu,
RHEL, SLES, Oracle Linux, Xen Server,...

This is the situation when we cut a new release. We **do not** backport compat
to older releases. If you use an "old" tarball (it could even be the latest
release from us) and Linux upstream moved forward then you might have to wait
for the next release (or do the compat work yourself). Too old compat can also
happen when distributions do kernel upgrades (e.g., usually when RHEL updates
from one dot release to another like 8.5 to 8.6). If that happens we have to
provide new compat for our customers anyways. They then get pre-built kernel
modules and we push the code to github. But again, we don't backport that new
compat to old releases for FLOSS users.

A word on CentOS Stream: It is not one of the distributions we care about too
deeply. You might be lucky because their kernel is reasonably compatible to
the RHEL kernel, but as they move faster things break faster. If you look for
a distribution that is now what CentOS once was (RHEL kernel compatible), then
we have very good experience with AlmaLinux. Rocky Linux should be fine as well.

# Releases
Releases generated by git tags on github are snapshots of the git repository at the given time. You most
likely do not want to use these. They might lack things such as generated man pages, the `configure` script,
and other generated files. If you want to build from a tarball, use the ones [provided by us](https://www.linbit.com/en/drbd-community/drbd-download/).
