FROM ubuntu:xenial
MAINTAINER Weaveworks Inc <help@weave.works>
LABEL works.weave.role=system

# Install BCC
RUN echo "deb [trusted=yes] http://repo.iovisor.org/apt/xenial xenial-nightly main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update && apt-get install -y libbcc libbcc-examples python-bcc

# Add our plugin
ADD ./ebpf-http-statistics.c ./http-statistics.py /usr/bin/
ENTRYPOINT ["/usr/bin/http-statistics.py"]
