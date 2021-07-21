// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <ctime>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <linux/limits.h>
#include <memory>
#include <unistd.h>
#include <vector>

#include "openenclave/common/sgx/tcbinfo.h"
#include "openenclave/host/sgx/quote.h"
#include "openenclave/include/openenclave/attestation/sgx/evidence.h"
#include "openenclave/include/openenclave/attestation/sgx/report.h"
#include "openenclave/include/openenclave/host.h"
#include "openenclave/include/openenclave/internal/error.h"
#include "openenclave/include/openenclave/internal/tests.h"

#include "hostapis_u.h"
#include "oefuzzer.h"

class hostapi_fuzzer : public oe_fuzzer_host
{
  public:
    hostapi_fuzzer()
    {
        std::string enc_path;
        if (get_proc_path(enc_path))
            enc_path.append("/hostapis_enc");

        if (access(enc_path.c_str(), F_OK) != 0)
        {
            char* setup_dir = getenv("ONEFUZZ_SETUP_DIR");
            if (setup_dir)
            {
                enc_path = setup_dir;
                enc_path.append("/hostapis_enc");
                printf("Enclave Path = %s\n", enc_path.c_str());
            }
        }

        assert(!access(enc_path.c_str(), F_OK));
        
        uint32_t flags = oe_get_create_flags();
        oe_result_t result =
            oe_create_hostapis_enclave(enc_path.c_str(), OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (result != OE_OK)
        {
            oe_put_err("Failed to create enclave, result=%u", result);
        }
    }

    ~hostapi_fuzzer()
    {
        if (enclave)
        {
            oe_result_t result = oe_terminate_enclave(enclave);
            if (result != OE_OK)
            {
                oe_put_err("Failed to terminate enclave, result=%u", result);
            }
        }
    }

  protected:
    oe_enclave_t *enclave = nullptr;
};

class get_report_fuzz : public hostapi_fuzzer
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(sgx_target_info_t))
            return OE_UNEXPECTED;

        sgx_target_info_t target_info = {};
        static oe_uuid_t sgx_ecdsa_uuid = {OE_FORMAT_UUID_SGX_EPID_LINKABLE};
        (void)sgx_get_qetarget_info(&sgx_ecdsa_uuid, NULL, 0, &target_info);

        uint32_t flags = 0;
        memcpy(&flags, data, sizeof(uint32_t));

        size_t report_buffer_size = 0;
        uint8_t *report_buffer_ptr = NULL;
        oe_result_t res =
            oe_get_report(enclave, flags, &target_info, sizeof(target_info), &report_buffer_ptr, &report_buffer_size);
        oe_free_report(report_buffer_ptr);
        return res;
    }
};

class get_target_info_fuzz : public hostapi_fuzzer
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(sgx_target_info_t))
            return OE_UNEXPECTED;

        sgx_target_info_t *target_info = NULL;
        size_t target_info_size = 0;
        oe_result_t res = oe_get_target_info(data, size, (void **)&target_info, &target_info_size);
        if (res == OE_OK && target_info)
            free(target_info);
        return res;
    }
};

class parse_report_fuzz : public hostapi_fuzzer
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_report_t))
            return OE_UNEXPECTED;

        oe_report_t parsed_report{};
        return oe_parse_report(data, size, &parsed_report);
    }
};

class verify_report_fuzz : public hostapi_fuzzer
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_report_t))
            return OE_UNEXPECTED;

        oe_report_t parsed_report{};
        return oe_verify_report(enclave, data, size, &parsed_report);
    }
};

class get_public_key_by_policy_fuzz : public hostapi_fuzzer
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_asymmetric_key_params_t))
            return OE_UNEXPECTED;

        uint32_t seal_policy = (uint32_t)*data;
        oe_asymmetric_key_params_t params;
        memcpy(&params, data, sizeof(params));
        params.user_data = NULL;

        uint8_t *pubkey = NULL;
        size_t pubkey_size = 0;
        uint8_t *keyinfo = NULL;
        size_t keyinfo_size = 0;

        (void)oe_get_public_key_by_policy(enclave, (oe_seal_policy_t)(seal_policy % OE_SEAL_POLICY_PRODUCT), &params,
                                          &pubkey, &pubkey_size, &keyinfo, &keyinfo_size);

        uint8_t *key_buffer;
        size_t key_buffer_size = 0;

        if (keyinfo)
        {
            oe_get_public_key(enclave, &params, keyinfo, keyinfo_size, &key_buffer, &key_buffer_size);
            oe_free_key(key_buffer, key_buffer_size, NULL, 0);
        }

        oe_free_key(pubkey, pubkey_size, keyinfo, keyinfo_size);
        return OE_OK;
    }
};

class get_public_key_fuzz : public hostapi_fuzzer
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_asymmetric_key_params_t))
            return OE_UNEXPECTED;

        uint32_t seal_policy = (uint32_t)*data;
        oe_asymmetric_key_params_t params;
        memcpy(&params, data, sizeof(params));
        params.user_data = NULL;

        uint8_t *key_buffer = NULL;
        size_t key_buffer_size = 0;

        oe_get_public_key(enclave, &params, data, size, &key_buffer, &key_buffer_size);

        oe_free_key(key_buffer, key_buffer_size, NULL, 0);
        return OE_OK;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::unique_ptr<hostapi_fuzzer> fuzzer;

#ifdef oe_get_report_host_fuzz
        fuzzer = std::make_unique<get_report_fuzz>();
#elif oe_get_target_info_host_fuzz
        fuzzer = std::make_unique<get_target_info_fuzz>();
#elif oe_parse_report_host_fuzz
        fuzzer = std::make_unique<parse_report_fuzz>();
#elif oe_verify_report_host_fuzz
        fuzzer = std::make_unique<verify_report_fuzz>();
#elif oe_get_public_key_by_policy_host_fuzz
        fuzzer = std::make_unique<get_public_key_by_policy_fuzz>();
#elif oe_get_public_key_host_fuzz
        fuzzer = std::make_unique<get_public_key_fuzz>();
#endif

    int retval = 0;
    if (fuzzer)
        retval = fuzzer->fuzz(data, size);

    return retval;
}

extern "C" void LLVMFuzzerFinalize() {}
