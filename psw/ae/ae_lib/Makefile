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

TOP_DIR  = ../../..
include $(TOP_DIR)/buildenv.mk

AE_LIB_DIR      := $(LINUX_PSW_DIR)/ae/ae_lib
AE_LE_DIR       := $(LINUX_PSW_DIR)/ae/le
AESM_SOURCE_DIR := $(LINUX_PSW_DIR)/ae/aesm_service/source
AESM_EXTENSION  := $(LINUX_PSW_DIR)/ae/aesm_service/source/aesm/extension

INCLUDE += -I. \
           -I$(COMMON_DIR)/inc \
           -I$(COMMON_DIR)/inc/internal \
           -I$(LINUX_PSW_DIR)/ae/inc \
           -I$(LINUX_PSW_DIR)/ae/inc/internal \
           -I$(LINUX_PSW_DIR)/ae/le \
           -I$(LINUX_PSW_DIR)/ae/aesm_service/include \
           -I$(AESM_SOURCE_DIR)/le \
           -I$(AESM_SOURCE_DIR)/aesm/extension \
           -I$(AESM_SOURCE_DIR)/aesm/application \
           -I$(AESM_SOURCE_DIR)/storage \
           -I$(LINUX_PSW_DIR)/ae/data/constants/linux \
           -I$(LINUX_EXTERNAL_DIR)/crypto_px/include

EDGER8R  := $(LINUX_SDK_DIR)/edger8r/linux/_build/Edger8r.native

ifdef PROFILE
        CXXFLAGS += -D_PROFILE_
        CFLAGS += -D_PROFILE_
endif

CXXFLAGS += -fPIC
CFLAGS := $(filter-out -fPIC -Werror, $(CFLAGS))

URTSLIB := -lurts_internal
WHITE_LIST_FILE := $(LINUX_PSW_DIR)/ae/data/prebuilt/white_list_cert_to_be_verify.bin

vpath %.c $(TOP_DIR)/sdk/tlibc/string

SRC :=  $(AE_LIB_DIR)/ae_lib.cpp \
        $(AESM_SOURCE_DIR)/le/LEClass.cpp \
        $(AESM_SOURCE_DIR)/oal/aesm_util.cpp \
        $(AESM_SOURCE_DIR)/storage/persistent_storage_table.cpp

OBJ := $(SRC:.cpp=.o)

VTUNE_LIBDIR := $(LINUX_EXTERNAL_DIR)/vtune/linux/sdk/src/ittnotify
ifeq ($(ARCH), x86)
    VTUNE_LIBDIR = $(LINUX_EXTERNAL_DIR)/vtune/linux/lib32
endif
TCRYPTO_LIBDIR  := $(LINUX_SDK_DIR)/tlibcrypto

EXTERNAL_LIB += -L$(VTUNE_LIBDIR) -littnotify -ldl
EXTERNAL_LIB += -L$(TCRYPTO_LIBDIR) -lsgx_tcrypto

LDUFLAGS := -pthread -L$(BUILD_DIR) $(URTSLIB)

LIBNAME           := libsgx_ae.so

.PHONY: all
all: $(LIBNAME) copy_data_file | $(BUILD_DIR)
	@$(CP) $< $|

copy_data_file:
	@$(MKDIR) -p data
	@$(CP) $(WHITE_LIST_FILE) data/white_list_cert_to_be_verify.bin

sgx_tcrypto:
	$(MAKE) -C $(TCRYPTO_LIBDIR)

.PHONY: urts
urts:
	$(MAKE) -C $(LINUX_PSW_DIR)/urts/linux

%.o :%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@
%.o :%.cc
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

$(LIBNAME): $(OBJ) sgx_tcrypto urts
	$(CXX) $(CXXFLAGS) $(OBJ) $(LDUFLAGS) $(EXTERNAL_LIB) -shared -Wl,-soname=$@ -o $@

$(AESM_SOURCE_DIR)/le/LEClass.o: ${AESM_EXTENSION}/launch_enclave_u.c

$(AESM_EXTENSION)/launch_enclave_u.c: ${LINUX_PSW_DIR}/ae/le/launch_enclave.edl
	@$(EDGER8R) --untrusted --untrusted-dir ${AESM_EXTENSION} $<

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean:
	@$(RM) -r data
	@$(RM) $(LIBNAME)
	$(MAKE) -C $(LINUX_PSW_DIR)/urts/linux clean
	@$(RM) $(AESM_SOURCE_DIR)/le/*.o
	@$(RM) $(AESM_SOURCE_DIR)/oal*.o
	@$(RM) $(AESM_SOURCE_DIR)/storage/*.o
	@$(RM) $(AESM_EXTENSION)/*_u.c $(AESM_EXTENSION)/*_u.h

.PHONY: rebuild
rebuild: clean all

