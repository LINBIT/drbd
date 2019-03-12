FROM ubuntu:bionic

COPY /pkgs.bionic /pkgs
RUN apt-get update && apt-get install -y kmod

COPY /entry.sh /
RUN chmod +x /entry.sh
ENTRYPOINT /entry.sh
