// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>

#include "openenclave/include/openenclave/corelibc/stdlib.h"
#include "openenclave/include/openenclave/enclave.h"
#include "openenclave/include/openenclave/internal/raise.h"
#include "openenclave/include/openenclave/internal/trace.h"

#include "enclaveapis_t.h"
#include "oefuzzer.h"

OE_SET_ENCLAVE_SGX(1,     /* ProductID */
                   1,     /* SecurityVersion */
                   true,  /* Debug */
                   25600, /* NumHeapPages */
                   2048,  /* NumStackPages */
                   2);    /* NumTCS */

class oe_get_report_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(sgx_target_info_t))
            return OE_UNEXPECTED;

        uint32_t flags = 0;
        memcpy(&flags, data, sizeof(uint32_t));

        uint8_t *report_buffer = NULL;
        size_t report_buffer_size = 0;
        oe_result_t res = oe_get_report(flags, data, size, data, size, &report_buffer, &report_buffer_size);
        oe_free_report(report_buffer);
        return res;
    }
};

class oe_get_target_info_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(sgx_target_info_t))
            return OE_UNEXPECTED;

        sgx_target_info_t *target_info = NULL;
        size_t target_info_size = 0;
        oe_result_t res = oe_get_target_info(data, size, (void **)&target_info, &target_info_size);
        oe_free_target_info(target_info);
        return res;
    }
};

class oe_parse_report_fuzz : public oe_fuzzer_enclave
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

class oe_verify_report_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_report_t))
            return OE_UNEXPECTED;

        oe_report_t parsed_report{};
        return oe_verify_report(data, size, &parsed_report);
    }
};

class oe_get_seal_key_by_policy_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_seal_policy_t))
            return OE_UNEXPECTED;

        uint8_t *key_buffer = NULL;
        size_t key_buffer_size = 0;
        uint8_t *key_info = NULL;
        size_t key_info_size = 0;

        uint32_t seal_policy = (uint32_t)*data;
        oe_result_t res = oe_get_seal_key_by_policy((oe_seal_policy_t)(seal_policy % OE_SEAL_POLICY_PRODUCT),
                                                    &key_buffer, &key_buffer_size, &key_info, &key_info_size);
        oe_free_seal_key(key_buffer, key_info);
        return res;
    }
};

class oe_get_public_key_by_policy_fuzz : public oe_fuzzer_enclave
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

        oe_result_t res = oe_get_public_key_by_policy((oe_seal_policy_t)(seal_policy % OE_SEAL_POLICY_PRODUCT), &params,
                                                      &pubkey, &pubkey_size, &keyinfo, &keyinfo_size);

        oe_free_key(pubkey, pubkey_size, keyinfo, keyinfo_size);
        return res;
    }
};

class oe_get_public_key_fuzz : public oe_fuzzer_enclave
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

        oe_result_t res = oe_get_public_key(&params, data, size, &key_buffer, &key_buffer_size);
        oe_free_key(key_buffer, key_buffer_size, NULL, 0);
        return res;
    }
};

class oe_get_private_key_by_policy_fuzz : public oe_fuzzer_enclave
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
        uint8_t *key_info = NULL;
        size_t key_info_size = 0;
        oe_result_t res =
            oe_get_private_key_by_policy((oe_seal_policy_t)(seal_policy % OE_SEAL_POLICY_PRODUCT), &params, &key_buffer,
                                         &key_buffer_size, &key_info, &key_info_size);

        oe_free_key(key_buffer, key_buffer_size, NULL, 0);
        return res;
    }
};

class oe_get_private_key_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(oe_asymmetric_key_params_t))
            return OE_UNEXPECTED;

        oe_asymmetric_key_params_t params;
        memcpy(&params, data, sizeof(params));
        params.user_data = NULL;

        uint8_t *key_buffer = NULL;
        size_t key_buffer_size = 0;
        oe_result_t res = oe_get_private_key(&params, data, size, &key_buffer, &key_buffer_size);
        oe_free_key(key_buffer, key_buffer_size, NULL, 0);
        return res;
    }
};

class oe_get_seal_key_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(sgx_key_request_t))
            return OE_UNEXPECTED;

        uint8_t *key_buffer = NULL;
        size_t key_buffer_size = 0;
        oe_result_t res = oe_get_seal_key(data, size, &key_buffer, &key_buffer_size);
        oe_free_seal_key(key_buffer, NULL);
        return res;
    }
};

class oe_generate_attestation_certificate_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        if (size < sizeof(sgx_key_request_t))
            return OE_UNEXPECTED;

        uint8_t *output_certificate = nullptr;
        size_t output_certificate_size = 0;
        const unsigned char *certificate_buffer_ptr = nullptr;
        static const unsigned char certificate_subject_name[] = "CN=Open Enclave SDK,O=OESDK TLS,C=US";

        oe_result_t res = oe_generate_attestation_certificate(certificate_subject_name, const_cast<uint8_t *>(data),
                                                              size, const_cast<uint8_t *>(data), size,
                                                              &output_certificate, &output_certificate_size);

        oe_free_attestation_certificate(output_certificate);
        return res;
    }
};

class oe_verify_attestation_certificate_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        return oe_verify_attestation_certificate(const_cast<uint8_t *>(data), size, NULL, NULL);
    }
};

std::unique_ptr<oe_fuzzer_enclave> fuzzer;
int oe_fuzz_ecall(const uint8_t *data, size_t size)
{
    if (!fuzzer)
    {
#ifdef oe_get_report_enc
        fuzzer = std::make_unique<oe_get_report_fuzz>();
#elif oe_get_target_info_enc
        fuzzer = std::make_unique<oe_get_target_info_fuzz>();
#elif oe_parse_report_enc
        fuzzer = std::make_unique<oe_parse_report_fuzz>();
#elif oe_verify_report_enc
        fuzzer = std::make_unique<oe_verify_report_fuzz>();
#elif oe_get_seal_key_by_policy_enc
        fuzzer = std::make_unique<oe_get_seal_key_by_policy_fuzz>();
#elif oe_get_public_key_by_policy_enc
        fuzzer = std::make_unique<oe_get_public_key_by_policy_fuzz>();
#elif oe_get_public_key_enc
        fuzzer = std::make_unique<oe_get_public_key_fuzz>();
#elif oe_get_private_key_by_policy_enc
        fuzzer = std::make_unique<oe_get_private_key_by_policy_fuzz>();
#elif oe_get_private_key_enc
        fuzzer = std::make_unique<oe_get_private_key_fuzz>();
#elif oe_get_seal_key_enc
        fuzzer = std::make_unique<oe_get_seal_key_fuzz>();
#elif oe_generate_attestation_certificate_enc
        fuzzer = std::make_unique<oe_generate_attestation_certificate_fuzz>();
#elif oe_verify_attestation_certificate_enc
        fuzzer = std::make_unique<oe_verify_attestation_certificate_fuzz>();
#endif
    }

    int retval = 0;
    if (fuzzer)
        retval = fuzzer->fuzz(data, size);

    return retval;
}

void oe_fuzz_cleanup_ecall()
{
    fuzzer.reset();
}
