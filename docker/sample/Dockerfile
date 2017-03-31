FROM ubuntu:14.04

ENV http_proxy http://proxy-us.intel.com:911
ENV https_proxy http://proxy-us.intel.com:912
ENV no_proxy intel.com,*.intel.com,127.0.0.1,localhost

RUN apt-get update && \
    apt-get install -y git build-essential ocaml automake autoconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c0-dev protobuf-compiler curl make g++ unzip wget libssl-dev python

RUN groupadd aesmd && useradd -m -s /bin/bash -g aesmd aesmd

USER aesmd
RUN cd ~ && git clone https://github.com/sean-jc/linux-sgx.git
RUN cd ~/linux-sgx && git checkout -b c/docker origin/c/docker
RUN cd ~/linux-sgx && \
    ./download_prebuilt.sh && \
    USE_OPT_LIBS=0 make psw_install_pkg

USER root
RUN mkdir -p /opt/intel && \
    cd /opt/intel && \
    /home/aesmd/linux-sgx/linux/installer/bin/sgx_linux_x64_psw_1.*.bin

# Install the PSW first and as a separate layer so that all layers
# up to and including the PSW can be shared between the AESM image
# and the SampleEnclave image.  For this same reason we use aesmd
# as the user even though aesmd is not the most appropriate name.
USER aesmd
RUN cd ~/linux-sgx && \
    USE_OPT_LIBS=0 make sdk_install_pkg

USER root
RUN cd /opt/intel && \
    sh -c 'echo yes | /home/aesmd/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_1.*.bin'

USER aesmd
RUN cd ~/linux-sgx/SampleCode/SampleEnclave && \
    SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

CMD cd /home/aesmd/linux-sgx/SampleCode/SampleEnclave && ./app
