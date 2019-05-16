FROM centos:centos8

COPY /pkgs.centos8 /pkgs

COPY /entry.sh /
RUN chmod +x /entry.sh
ENTRYPOINT /entry.sh
