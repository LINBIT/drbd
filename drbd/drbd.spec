Name: drbd
Summary: Distributed Redundant Block Device driver for Linux
#Version: %(cat Makefile.vars | grep "^REL_VERSION" | gawk '{ print $3 }' | sed 's/-//')
Version: 0.6.1pre16
Release: 1
Source: %{name}-%{version}.tar.gz
Vendor: DRBD 
License: GPL
ExclusiveOS: linux
Group: System Environment/Kernel
Requires: kernel
Provides: %{name}
URL: http://www.complang.tuwien.ac.at/reisner/drbd/ 
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Drbd is a block device which is designed to build high availability clusters.
This is done by mirroring a whole block device via (a dedicated) network.
You could see it as a network RAID 1.

%prep
%setup

%build
mkdir -p %{buildroot}

make clean
make PREFIX=%{buildroot}/ MANDIR=%{_mandir} all install

%install
cd %{buildroot}
find lib/modules -name drbd.o -exec mv {} {}.new \; \
         -fprintf %{_builddir}/%{name}-%{version}/file.list "/%p.new\n"

%clean
rm -rf %{buildroot}

%files -f %{_builddir}/%{name}-%{version}/file.list
%defattr(-,root,root)
%{_mandir}/man8/datadisk.8.gz
%{_mandir}/man8/drbd.8.gz
%{_mandir}/man8/drbdsetup.8.gz
%{_mandir}/man5/drbd.conf.5.gz
/usr/sbin/drbdsetup
/etc/rc.d/init.d/drbd
/etc/ha.d/resource.d/datadisk
%doc scripts/drbd.conf
%doc documentation/NFS-Server-README.txt
%doc COPYING
%doc README
%doc file.list

%post
FL=%{_docdir}/%{name}-%{version}/file.list

if [ $1 -eq 1 ]; then
	for d in $(sed 's/^\(\/lib\/modules\/[^/]*\).*/\1/' $FL) ; do
		find $d -name drbd.o -exec mv -f {} {}.old \;
	done
fi
for f in $(sed 's/\.new$//' $FL) ; do
	ln -f $f.new $f 
done

uname -r | grep BOOT || /sbin/depmod -a > /dev/null 2>&1 || true

chkconfig --add drbd

%preun
FL=%{_docdir}/%{name}-%{version}/file.list

if [ $1 -eq 0 ]; then
	for f in $(sed 's/\.new$//' $FL) ; do
		rm $f
	done
	for d in $(sed 's/^\(\/lib\/modules\/[^/]*\).*/\1/' $FL) ; do
		for f in $(find $d -name drbd.o.old -print) ; do
			mv $f $(echo $f | sed 's/\.old$//')
		done
	done
fi

service drbd stop

lsmod | grep drbd > /dev/null 2>&1
if [ $? -eq 0 ]; then
	rmmod drbd
fi

chkconfig --del drbd

%postun
uname -r | grep BOOT || /sbin/depmod -a > /dev/null 2>&1 || true

%changelog
* Wed Aug 14 2002 Omar Kilani <ok@mailcall.com.au>
- Initial revision (a very hacked up e1000.spec file)
