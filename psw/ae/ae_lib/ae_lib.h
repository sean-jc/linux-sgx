/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _AE_LIB_H_
#define _AE_LIB_H_

#include <time.h>
#include <string.h>

#include "aeerror.h"
#include "aesm_error.h"
#include "arch.h"
#include "sgx_urts.h"
#include "internal/se_stdio.h"
#include "internal/se_memcpy.h"
#include "internal/uncopyable.h"
#include "oal/internal_log.h"

class AELibMutex{
    CLASS_UNCOPYABLE(AELibMutex)
public:
    AELibMutex() {se_mutex_init(&mutex);}
    ~AELibMutex() { se_mutex_destroy(&mutex);}
    void lock() { se_mutex_lock(&mutex); }
    void unlock() { se_mutex_unlock(&mutex); }
private:
    se_mutex_t mutex;
};

class AELibLock {
    CLASS_UNCOPYABLE(AELibLock)
public:
    explicit AELibLock(AELibMutex& cs) :_cs(cs) { _cs.lock(); }
    ~AELibLock() { _cs.unlock(); }
private:
    AELibMutex& _cs;
};

class AELib{
public:
    static AELibMutex _le_mutex; /*mutex to lock external interface*/
private:
    static ae_error_t save_unverified_white_list(const uint8_t *white_list_cert, uint32_t white_list_cert_size);
    static ae_error_t get_white_list_size_without_lock(uint32_t *white_list_cert_size);
    static ae_error_t set_psvn(uint16_t prod_id, uint16_t isv_svn, sgx_cpu_svn_t cpu_svn, uint32_t mrsigner_index);
public:
    static sgx_status_t get_launch_token(const enclave_css_t* signature,
        const sgx_attributes_t* attribute,
        sgx_launch_token_t* launch_token);

    static aesm_error_t get_launch_token(
        const uint8_t *mrenclave,  uint32_t mrenclave_size,
        const uint8_t *public_key, uint32_t public_key_size,
        const uint8_t *se_attributes, uint32_t se_attributes_size,
        uint8_t * lictoken, uint32_t lictoken_size);

    static aesm_error_t white_list_register(
        const uint8_t *white_list_cert, uint32_t white_list_cert_size);

    static aesm_error_t get_white_list_size(
        uint32_t* white_list_cert_size);

    static aesm_error_t get_white_list(
        uint8_t *white_list_cert, uint32_t buf_size);
};

#define AESMLogicLock AELibLock
#define AESMLogic AELib

#endif

