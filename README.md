
[![Open Source](https://github.com/yusufyildiz/drbd/blob/drbd-9.0/misc/drbd_logo.png?raw=true)](https://www.linbit.com/linstor)

[![Open Source](https://img.shields.io/badge/Open-Source-brightgreen)](https://opensource.org/) [![GPLv3 License](https://img.shields.io/badge/License-GPL%20v2-brightgreen.svg)](https://opensource.org/licenses/) [![Slack Channel](https://img.shields.io/badge/Slack-Channel-brightgreen)](https://join.slack.com/t/linbit-community/shared_invite/enQtOTg0MTEzOTA4ODY0LTFkZGY3ZjgzYjEzZmM2OGVmODJlMWI2MjlhMTg3M2UyOGFiOWMxMmI1MWM4Yjc0YzQzYWU0MjAzNGRmM2M5Y2Q) [![Support](https://img.shields.io/badge/$-support-12a0df.svg?style=flat)](https://www.linbit.com/support/) [![Active](http://img.shields.io/badge/Status-Active-green.svg)](https://linbit.com/drbd) [![GitHub Commit](https://img.shields.io/github/commit-activity/y/linbit/drbd)]() 

 
 
# What is DRBD®

DRBD® developed by [LINBIT](https://www.linbit.com/), is a distributed replicated storage system for the Linux platform. It is implemented as a kernel driver, several userspace management applications, and some shell scripts.  

DRBD is traditionally used in high availability (HA) computer clusters, but beginning with DRBD version 9, it can also be used to create larger software defined storage pools with a focus on cloud integration. 

DRBD keeps disks on multiple nodes synchronized using TCP/IP or RDMA and makes the data available as a block device. This results in RAID 1 but without the use of uncommon hardware such as shared SCSI buses or Fibre Channel.

This repository contains the Linux kernel code for DRBD version 9 and above.


## How it works

 [![](https://mldatnmifxoe.i.optimole.com/Q4Tiw9A-Rd_QXhW6/w:500/h:504/q:auto/https://www.linbit.com/wp-content/uploads/2020/03/DRBD-Diagram.jpg)](https://www.linbit.com/drbd/)  



DRBD is split into two independent pieces: a kernel module that implements the DRBD behaviours and a set of user-space administration applications used to manage the DRBD disks. 

The kernel module implements a driver for a virtual block device (which is replicated between a local disk and a remote disk across the network). As a virtual disk, DRBD provides a flexible model that a variety of applications can use (from file systems to other applications that can rely on a raw disk, such as a database). The DRBD module implements an interface not only to the underlying block driver (as defined by the disk configuration item in drbd.conf) but also the networking stack (whose endpoint is defined by an IP address and port number, also in drbd.conf).

#### Administrating DRBD

###### drbdsetup
drbdsetup is the low level tool that interacts with the DRBD kernel driver. It manages the DRBD objects (resources, connections, devices, paths). It can modify all properties, and can dump the kernel driver’s active configuration. It displays status and status updates.

###### drbdmeta
drbdmeta is used to prepare meta-data on block devices before they can be used for DRBD. You can use it to dump and inspect this meta-data as well. It is comparable to mkfs or pvcreate.

###### drbdadm
drbdadm processes configuration declarative configuration files. Those files are identical on all nodes of an installation. drbdadm extracts the necessary information for the host it is invoked on.

#### DRBD Replication Modes

DRBD Supports three replication modes,
1. Protocol A - Asynchronous replication protocol. Local write operations on the primary node are considered completed as soon as the local disk write has finished, and the replication packet has been placed in the local TCP send buffer. In the event of forced fail-over, data loss may occur.

2. Protocol B - Memory synchronous (semi-synchronous) replication protocol. Local write operations on the primary node are considered completed as soon as the local disk write has occurred, and the replication packet has reached the peer node. Normally, no writes are lost in case of forced fail-over.

3. Protocol C - Synchronous replication protocol. Local write operations on the primary node are considered completed only after both the local and the remote disk write have been confirmed. As a result, loss of a single node is guaranteed not to lead to any data loss.

## Features
- Open Source

- Main Features
  - Provides replicated block storage for all kind of hardware / virtualized platform.
  - Support for High Availibility & Disaster Recovery scenarios
  - Compatible with high I/O workloads like databases
  - Choose your own Linux filesystem

- Storage Related Features
  - Network replication
  - Management of persistent Memory (PMEM)
  - ZFS support
  - NVME over Fabrics support


- Network Related Features
  - Replicate via multiple network cards
  - TCP/IP support
  - RDMA Support
  - Automatic management of TCP/IP port range, minor number range etc. provides consistent data
  - Scale-up and scale-out
 
 
## User Guide

DRBD is developed and maintained by LINBIT. User Guide is available through LINBIT website.
For a more detailed installation guide, please follow the link below.

[![LINSTOR GUIDE](https://img.shields.io/badge/DRBD-USER_GUIDE-orange)](https://www.linbit.com/drbd-user-guide/drbd-guide-9_0-en/) 


## Support

DRBD is an open source software. You can use our slack channel above link to get support for individual use and development use.
If you are going to use it in enterprise and mission critical environments, please contact us via the link below for professional support.

[![DRBD Support](https://img.shields.io/badge/DRBD-SUPPORT-brightgreen)](https://www.linbit.com/support/) 


## Releases

Releases generated by git tags on github are snapshots of the git repository at the given time. They might lack things such as generated man pages, the configure script, and other generated files. If you want to build from a tarball, use the ones [provided by us](https://www.linbit.com/linbit-software-download-page-for-linstor-and-drbd-linux-driver/).

Also for alternative, please look at the "Building" section below. 

## Building

Since version 9.0.20, DRBD has been using a kernel backwards compatibility system based on Coccinelle semantic patches. While this has many advantages, it also makes it a little harder for "casual" developers to build DRBD from the git sources. The problem is that we require a very recent version of spatch (at least 1.0.8 at time of writing), and most distributions only have relatively old versions in their repositories.

### From git
For users wishing to build DRBD from its git sources, here are a few options:

- Use a recent kernel. When building against a recent(ish) upstream kernel, chances are you won't even have to use any of the compat features, which means you won't require compatibility patches and in turn don't need spatch installed.
- On Ubuntu 18.04 and newer, use a recent spatch version from the Coccinelle PPA. This provides (at time of writing) version 1.0.8, which is recent enough to build DRBD.
- Build and install spatch from source. This will also give you a version that is recent enough to build DRBD.

### From a release tarball

For use cases where it is appropriate to just build DRBD from a release tarball, here are some options:

- Use a distribution kernel and rely on the shipped "compat patch cache". We pre-generate compatibility patches for a list of commonly used distribution kernels and ship them with every release tarball. If your kernel matches one of those in the cache, you won't need spatch because the cached patch will be applied directly.
- For all other kernels, you can use LINBIT's "spatch as a service" online service, which transparently and automatically generates compatibility patches based on your kernels feature set.
- If you are using an exotic kernel and you do not have internet access or otherwise can't or don't want to use "spatch as a service", you will have to install a recent version of coccinelle (see above).

For a release tarball, these options should be handled transparently for the user. In other words, if you download a tarball and type "make", it should work in next to all cases.


**Free Software, Hell Yeah!**

[![DRBD Powered by LINBIT](https://github.com/yusufyildiz/lstest2/blob/master/img/poweredby_linbit_small.png?raw=true)](https://www.linbit.com/linstor/) 
