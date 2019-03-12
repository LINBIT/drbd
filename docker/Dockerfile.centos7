FROM centos:centos7

COPY /pkgs.centos7 /pkgs

COPY /entry.sh /
RUN chmod +x /entry.sh
ENTRYPOINT /entry.sh
