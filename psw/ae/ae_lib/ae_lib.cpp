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

#include <assert.h>
#include <time.h>
#include <string>

#include "LEClass.h"

#include "ae_lib.h"
#include "arch.h"
#include "byte_order.h"
#include "util.h"
// #include "se_wrapper.h"
#include "ippcp.h"
#include "ippcore.h"
#include "se_trace.h"
#include "service_enclave_mrsigner.hh"

#define CHECK_SERVICE_STATUS

AELibMutex AELib::_le_mutex;

ae_error_t AELib::save_unverified_white_list(const uint8_t *white_list_cert, uint32_t white_list_cert_size)
{
    wl_cert_chain_t old_cert;
    const wl_cert_chain_t *p_new_cert = reinterpret_cast<const wl_cert_chain_t *>(white_list_cert);
    uint32_t old_cert_size = sizeof(old_cert);
    memset(&old_cert, 0, sizeof(old_cert));
    if((aesm_read_data(FT_PERSISTENT_STORAGE, AESM_WHITE_LIST_CERT_TO_BE_VERIFY_FID, reinterpret_cast<uint8_t *>(&old_cert), &old_cert_size) == AE_SUCCESS)
        && (old_cert_size == sizeof(old_cert)) && (white_list_cert_size >= sizeof(wl_cert_chain_t)))
    {
        if(_ntohl(p_new_cert->wl_cert.wl_version) <= _ntohl(old_cert.wl_cert.wl_version))
        {
            AESM_DBG_WARN("White list version downgraded! current version is %d, new version is %d",
                          _ntohl(old_cert.wl_cert.wl_version), _ntohl(p_new_cert->wl_cert.wl_version));
            return OAL_PARAMETER_ERROR;  // OAL_PARAMETER_ERROR used here is to indicate the white list is incorrect
        }
    }
    return aesm_write_data(FT_PERSISTENT_STORAGE, AESM_WHITE_LIST_CERT_TO_BE_VERIFY_FID, white_list_cert, white_list_cert_size);
}

aesm_error_t AELib::white_list_register(
        const uint8_t *white_list_cert, uint32_t white_list_cert_size)
{
    AESM_DBG_INFO("enter function");
    CHECK_SERVICE_STATUS;
    AELibLock lock(_le_mutex);
    CHECK_SERVICE_STATUS;
    ae_error_t ret_le = AE_SUCCESS;
    if (NULL == white_list_cert||0==white_list_cert_size){
        AESM_DBG_TRACE("Invalid parameter");
        return AESM_PARAMETER_ERROR;
    }
    ae_error_t ae_ret = CLEClass::instance().load_enclave();
    if(ae_ret == AE_SERVER_NOT_AVAILABLE)
    {
        AESM_DBG_WARN("LE not loaded due to AE_SERVER_NOT_AVAILABLE, possible SGX Env Not Ready");
        ret_le = save_unverified_white_list(white_list_cert, white_list_cert_size);
    }
    else if(AE_FAILED(ae_ret))
    {
        AESM_DBG_ERROR("LE not loaded:%d", ae_ret);
        return AESM_UNEXPECTED_ERROR;
    }else{
        ret_le = static_cast<ae_error_t>(CLEClass::instance().white_list_register(
            white_list_cert, white_list_cert_size));
    }

    switch (ret_le)
    {
    case AE_SUCCESS:
        return AESM_SUCCESS;
    case LE_INVALID_PARAMETER:
        AESM_DBG_TRACE("Invalid parameter");
        return AESM_PARAMETER_ERROR;
    case LE_INVALID_ATTRIBUTE:
        AESM_DBG_TRACE("Launch token error");
        return AESM_GET_LICENSETOKEN_ERROR;
    default:
        AESM_DBG_WARN("unexpeted error %d", ret_le);
        return AESM_UNEXPECTED_ERROR;
    }
}

aesm_error_t AELib::get_launch_token(
    const uint8_t * mrenclave, uint32_t mrenclave_size,
    const uint8_t *public_key, uint32_t public_key_size,
    const uint8_t *se_attributes, uint32_t se_attributes_size,
    uint8_t * lictoken, uint32_t lictoken_size)
{
    AESM_DBG_INFO("enter function");

    CHECK_SERVICE_STATUS;
    AELibLock lock(_le_mutex);
    CHECK_SERVICE_STATUS;

    ae_error_t ret_le = AE_SUCCESS;
    if (NULL == mrenclave ||
        NULL == public_key ||
        NULL == se_attributes ||
        NULL == lictoken)
    {
        //sizes are checked in CLEClass::get_launch_token()
        AESM_DBG_TRACE("Invalid parameter");
        return AESM_PARAMETER_ERROR;
    }
    ae_error_t ae_ret = CLEClass::instance().load_enclave();
    if(ae_ret == AESM_AE_NO_DEVICE)
    {
        AESM_DBG_FATAL("LE not loaded due to AE_SERVER_NOT_AVAILABLE, possible SGX Env Not Ready");
        return AESM_NO_DEVICE_ERROR;
    }
    else if(ae_ret == AESM_AE_OUT_OF_EPC)
    {
        AESM_DBG_WARN("LE not loaded due to out of EPC", ae_ret);
        return AESM_OUT_OF_EPC;
    }
    else if(AE_FAILED(ae_ret))
    {
        AESM_DBG_ERROR("LE not loaded:%d", ae_ret);
        return AESM_SERVICE_UNAVAILABLE;
    }
    ret_le = static_cast<ae_error_t>(CLEClass::instance().get_launch_token(
        const_cast<uint8_t *>(mrenclave), mrenclave_size,
        const_cast<uint8_t *>(public_key), public_key_size,
        const_cast<uint8_t *>(se_attributes), se_attributes_size,
        lictoken, lictoken_size));

    switch (ret_le)
    {
    case AE_SUCCESS:
        return AESM_SUCCESS;
    case LE_INVALID_PARAMETER:
        AESM_DBG_TRACE("Invalid parameter");
        return AESM_PARAMETER_ERROR;
    case LE_INVALID_ATTRIBUTE:
    case LE_INVALID_PRIVILEGE_ERROR:
        AESM_DBG_TRACE("Launch token error");
        return AESM_GET_LICENSETOKEN_ERROR;
    case LE_WHITELIST_UNINITIALIZED_ERROR:
        AESM_DBG_TRACE("LE whitelist uninitialized error");
        return AESM_UNEXPECTED_ERROR;
    default:
        AESM_DBG_WARN("unexpeted error %d", ret_le);
        return AESM_UNEXPECTED_ERROR;
    }
}

extern "C" sgx_status_t get_launch_token(const enclave_css_t* signature,
                                         const sgx_attributes_t* attribute,
                                         sgx_launch_token_t* launch_token)
{
    AESM_DBG_INFO("enter function");
    return AELib::get_launch_token(signature, attribute, launch_token);
}

sgx_status_t AELib::get_launch_token(const enclave_css_t* signature,
                                         const sgx_attributes_t* attribute,
                                         sgx_launch_token_t* launch_token)
{
    AESM_DBG_INFO("enter function");
    AELibLock lock(_le_mutex);

    ae_error_t ret_le = AE_SUCCESS;
    uint32_t mrsigner_index = UINT32_MAX;
    // load LE to get launch token
    if((ret_le=CLEClass::instance().load_enclave()) != AE_SUCCESS)
    {
        if(ret_le == AESM_AE_NO_DEVICE)
        {
            AESM_DBG_FATAL("LE not loaded due to no SGX device available, possible SGX Env Not Ready");
            return SGX_ERROR_NO_DEVICE;
        }
        else if(ret_le == AESM_AE_OUT_OF_EPC)
        {
            AESM_DBG_FATAL("LE not loaded due to out of EPC");
            return SGX_ERROR_OUT_OF_EPC;
        }
        else
        {
            AESM_DBG_FATAL("fail to load LE:%d",ret_le);
            return SGX_ERROR_SERVICE_UNAVAILABLE;
        }
    }


    ret_le = static_cast<ae_error_t>(CLEClass::instance().get_launch_token(
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t *>(&signature->body.enclave_hash)),
        sizeof(sgx_measurement_t),
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t *>(&signature->key.modulus)),
        sizeof(signature->key.modulus),
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t *>(attribute)),
        sizeof(sgx_attributes_t),
        reinterpret_cast<uint8_t*>(launch_token),
        sizeof(token_t),
        &mrsigner_index));
    switch (ret_le)
    {
    case AE_SUCCESS:
        break;
    case LE_INVALID_PARAMETER:
        AESM_DBG_TRACE("Invalid parameter");
        return SGX_ERROR_INVALID_PARAMETER;
    case LE_INVALID_ATTRIBUTE:
    case LE_INVALID_PRIVILEGE_ERROR:
        AESM_DBG_TRACE("Launch token error");
        return SGX_ERROR_SERVICE_INVALID_PRIVILEGE;
    case LE_WHITELIST_UNINITIALIZED_ERROR:
        AESM_DBG_TRACE("LE whitelist uninitialized error");
        return SGX_ERROR_UNEXPECTED;
    default:
        AESM_DBG_WARN("unexpeted error %d", ret_le);
        return SGX_ERROR_UNEXPECTED;
    }

    token_t *lt = reinterpret_cast<token_t *>(launch_token);
    ret_le = set_psvn(signature->body.isv_prod_id, signature->body.isv_svn, lt->cpu_svn_le, mrsigner_index);
    if(AE_PSVN_UNMATCHED_ERROR == ret_le)
    {
        //QE or PSE has been changed, but AESM doesn't restart. Will not provide service.
        return SGX_ERROR_SERVICE_UNAVAILABLE;
    }else if(AE_SUCCESS != ret_le) {
        AESM_DBG_ERROR("fail to save psvn:%d", ret_le);
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

ae_error_t AELib::get_white_list_size_without_lock(uint32_t *white_list_cert_size)
{
    uint32_t white_cert_size = 0;
    ae_error_t ae_ret = aesm_query_data_size(FT_PERSISTENT_STORAGE, AESM_WHITE_LIST_CERT_FID, &white_cert_size);
    if (AE_SUCCESS == ae_ret)
    {
        if (white_cert_size != 0){//file existing and not 0 size
            *white_list_cert_size = white_cert_size;
            return AE_SUCCESS;
        }
        else
            return AE_FAILURE;
    }
    else
    {
        return ae_ret;
    }
}

aesm_error_t AELib::get_white_list_size(
        uint32_t* white_list_cert_size)
{
    if (NULL == white_list_cert_size){
        return AESM_PARAMETER_ERROR;
    }
    CHECK_SERVICE_STATUS;
    AELibLock lock(_le_mutex);
    CHECK_SERVICE_STATUS;
    ae_error_t ae_ret = get_white_list_size_without_lock(white_list_cert_size);
    if (AE_SUCCESS == ae_ret)
        return AESM_SUCCESS;
    else
        return AESM_UNEXPECTED_ERROR;
}


aesm_error_t AELib::get_white_list(
    uint8_t *white_list_cert, uint32_t buf_size)
{
    uint32_t white_cert_size=0;
    if (NULL == white_list_cert){
        return AESM_PARAMETER_ERROR;
    }
    CHECK_SERVICE_STATUS;
    AELibLock lock(_le_mutex);
    CHECK_SERVICE_STATUS;
    ae_error_t ae_ret = get_white_list_size_without_lock(&white_cert_size);
    if (AE_SUCCESS != ae_ret)
        return AESM_UNEXPECTED_ERROR;
    if (white_cert_size != buf_size)
    {
        return AESM_PARAMETER_ERROR;
    }

    ae_ret = aesm_read_data(FT_PERSISTENT_STORAGE, AESM_WHITE_LIST_CERT_FID, white_list_cert, &white_cert_size);
    if (AE_SUCCESS != ae_ret){
        AESM_DBG_WARN("Fail to read white cert list file");
        return AESM_UNEXPECTED_ERROR;
    }
    return AESM_SUCCESS;
}

ae_error_t sgx_error_to_ae_error(sgx_status_t status)
{
    if(SGX_ERROR_OUT_OF_MEMORY == status)
        return AE_OUT_OF_MEMORY_ERROR;
    if(SGX_SUCCESS == status)
        return AE_SUCCESS;
    return AE_FAILURE;
}

ae_error_t AELib::set_psvn(uint16_t prod_id, uint16_t isv_svn, sgx_cpu_svn_t cpu_svn, uint32_t mrsigner_index)
{
    UNUSED(prod_id);
    UNUSED(isv_svn);
    UNUSED(cpu_svn);
    UNUSED(mrsigner_index);
    return AE_SUCCESS;
}

#ifdef DBG_LOG

static char half_byte_to_char(int x)
{
    assert(0<=x&&x<=0xF);
    if(0<=x&&x<=9)return (char)('0'+x);
    else return (char)('A'+x-10);
}

void aesm_dbg_format_hex(const uint8_t *data, uint32_t data_len, char *out_buf, uint32_t buf_size)
{
    uint32_t i;
    assert(buf_size>0);
    if(data_len==0){
        out_buf[0]='\0';
        return;
    }
    if(buf_size/3>=data_len){
        for(i=0;i<data_len;i++){
            int low=data[i]&0xF;
            int high=(data[i]>>4)&0xF;
            out_buf[i*3]=half_byte_to_char(high);
            out_buf[i*3+1]=half_byte_to_char(low);
            out_buf[i*3+2]=' ';
        }
        out_buf[data_len*3-1]='\0';
    }else if(buf_size>10){
        uint32_t tcount=buf_size/3-1;
        uint32_t off;
        uint32_t ecount=tcount/2,bcount=tcount-ecount;
        for(i=0;i<bcount;i++){
            int low=data[i]&0xF;
            int high=(data[i]>>4)&0xF;
            out_buf[i*3]=half_byte_to_char(high);
            out_buf[i*3+1]=half_byte_to_char(low);
            out_buf[i*3+2]=' ';
        }
        out_buf[i*3]=out_buf[i*3+1]=out_buf[i*3+2]='.';
        off=i*3+3;
        for(i=0;i<ecount;i++){
            int low=data[data_len-ecount+i]&0xF;
            int high=(data[data_len-ecount+i]>>4)&0xF;
            out_buf[off+i*3]=half_byte_to_char(high);
            out_buf[off+i*3+1]=half_byte_to_char(low);
            out_buf[off+i*3+2]=' ';
        }
        out_buf[off+i*3-1]='\0';
    }else{
        for(i=0;/*i<data_len&&*/i<(buf_size-1)/3;i++){//checking for i<data_len is redundant since first if condition in the function has filtered it
            int low=data[i]&0xF;
            int high=(data[i]>>4)&0xF;
            out_buf[i*3]=half_byte_to_char(high);
            out_buf[i*3+1]=half_byte_to_char(low);
            out_buf[i*3+2]=' ';
        }
        out_buf[i*3]='\0';
    }
}

void aesm_internal_log(const char *file_name, int line_no, const char *func_name, int level, const char *fmt, ...)
{
    va_list args;
    FILE *out = (level < INFO_LOG_LEVEL) ? stdout : stderr;

    fprintf(out, "[%s %d:%s] ", file_name, line_no, func_name);
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    fprintf(out, "\n");
}

#endif
