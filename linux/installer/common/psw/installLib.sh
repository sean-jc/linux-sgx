#!/usr/bin/env bash
#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


set -e

SCRIPT_DIR=$(dirname "$0")
source ${SCRIPT_DIR}/installConfig

PSW_DST_PATH=${SGX_PACKAGES_PATH}/${PSW_PKG_NAME}
AE_LIB_PATH=$PSW_DST_PATH/ae_lib

# /var/opt/aesmd is hardcoded into aesm_util.cpp
mkdir -p /var/opt/aesmd
cp -rf $AE_LIB_PATH/data /var/opt/aesmd/
rm -rf $AE_LIB_PATH

cat > $PSW_DST_PATH/uninstall.sh <<EOF
#!/usr/bin/env bash

if test \$(id -u) -ne 0; then
    echo "Root privilege is required."
    exit 1
fi

# Removing AESM internal folder
rm -fr /var/opt/aesmd

# Removing runtime libraries
rm -f /usr/lib/libsgx_ae.so
rm -f /usr/lib/libsgx_le.signed.so
rm -f /usr/lib/le_prod_css.bin
rm -f /usr/lib/libsgx_urts.so

# Removing AE lib folder
rm -fr $PSW_DST_PATH
EOF

chmod +x $PSW_DST_PATH/uninstall.sh

echo -e "\nuninstall.sh script generated in $PSW_DST_PATH\n"

echo -e "Installation is successful!"

rm -fr $PSW_DST_PATH/scripts

exit 0
