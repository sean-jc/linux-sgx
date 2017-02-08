FROM ubuntu:14.04

ENV http_proxy http://proxy-us.intel.com:911
ENV https_proxy http://proxy-us.intel.com:912
ENV no_proxy intel.com,*.intel.com,127.0.0.1,localhost

RUN apt-get update && \
    apt-get install -y git build-essential ocaml automake autoconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c0-dev protobuf-compiler curl make g++ unzip wget libssl-dev python

RUN groupadd sample && useradd -m -s /bin/bash -g sample sample

USER sample
RUN cd ~ && git clone https://github.com/01org/linux-sgx.git
COPY *.patch /home/sample/linux-sgx/
RUN cd ~/linux-sgx && \
    git apply *.patch && \
    cd ~/linux-sgx/sdk && USE_OPT_LIBS=0 make && \
    cd ~/linux-sgx/psw && make urts && \
    ~/linux-sgx/linux/installer/bin/build-installpkg.sh psw && \
    ~/linux-sgx/linux/installer/bin/build-installpkg.sh sdk

USER root
RUN mkdir -p /opt/intel && \
    cd /opt/intel && \
    /home/sample/linux-sgx/linux/installer/bin/sgx_linux_x64_psw_1.*.bin && \
    sh -c 'echo yes | /home/sample/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_1.*.bin'

USER sample
RUN cd ~/linux-sgx/SampleCode/SampleEnclave && \
    SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

CMD cd /home/sample/linux-sgx/SampleCode/SampleEnclave && ./app