FROM ubuntu:bionic

RUN apt-get update && apt-get install -y \
	    devscripts git build-essential make \
	    libpython2.7 software-properties-common jq && \
	    rm -rf /var/lib/apt/lists/*

RUN add-apt-repository -y ppa:npalix/coccinelle && apt-get update && \
	    apt-get install -y coccinelle && \
	    rm -rf /var/lib/apt/lists/*
