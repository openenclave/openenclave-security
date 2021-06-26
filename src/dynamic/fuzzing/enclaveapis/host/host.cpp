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

#include "oefuzzer.h"
#include "enclaveapis_u.h"

#ifdef oe_get_report_enc_fuzz
    #define ENCLAVE "/oe_get_report_enc"
#elif oe_get_target_info_enc_fuzz
    #define ENCLAVE "/oe_get_target_info_enc"
#elif oe_parse_report_enc_fuzz
    #define ENCLAVE "/oe_parse_report_enc"
#elif oe_verify_report_enc_fuzz
    #define ENCLAVE "/oe_verify_report_enc"
#elif oe_get_seal_key_by_policy_enc_fuzz
    #define ENCLAVE "/oe_get_seal_key_by_policy_enc"
#elif oe_get_public_key_by_policy_enc_fuzz
    #define ENCLAVE "/oe_get_public_key_by_policy_enc"
#elif oe_get_public_key_enc_fuzz
    #define ENCLAVE "/oe_get_public_key_enc"
#elif oe_get_private_key_by_policy_enc_fuzz
    #define ENCLAVE "/oe_get_private_key_by_policy_enc"
#elif oe_get_private_key_enc_fuzz
    #define ENCLAVE "/oe_get_private_key_enc"
#elif oe_get_seal_key_enc_fuzz
    #define ENCLAVE "/oe_get_seal_key_enc"
#elif oe_generate_attestation_certificate_enc_fuzz
    #define ENCLAVE "/oe_generate_attestation_certificate_enc"
#elif oe_verify_attestation_certificate_enc_fuzz
    #define ENCLAVE "/oe_verify_attestation_certificate_enc"
#endif

class enclaveapi_fuzzer : public oe_fuzzer_host
{
  public:
    enclaveapi_fuzzer()
    {
        std::string enc_path;
        if (get_proc_path(enc_path))
            enc_path.append(ENCLAVE);

        if (access(enc_path.c_str(), F_OK) != 0)
        {
            char* setup_dir = getenv("ONEFUZZ_SETUP_DIR");
            if (setup_dir)
            {
                enc_path = setup_dir;
                enc_path.append(ENCLAVE);
                printf("Enclave Path = %s\n", enc_path.c_str());
            }
        }

        assert(!access(enc_path.c_str(), F_OK));
        uint32_t flags = oe_get_create_flags();
        oe_result_t result = oe_create_enclaveapis_enclave(enc_path.c_str(), OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (result != OE_OK)
        {
            oe_put_err("Failed to create encalve, result=%u", result);
        }
        oe_log_init_ecall(enclave, enc_path.c_str(), 2);
    }

    ~enclaveapi_fuzzer()
    {
        if (enclave)
        {
            oe_result_t result = oe_fuzz_cleanup_ecall(enclave);
            if (result != OE_OK)
                oe_put_err("oe_fuzz_cleanup_ecall failed, result=%u", result);

            result = oe_terminate_enclave(enclave);
            if (result != OE_OK)
                oe_put_err("Failed to terminate encalve, result=%u", result);
        }
    }

    int fuzz(const uint8_t *data, size_t size)
    {
        int retval = 0;        
        if (enclave_status == OE_ENCLAVE_ABORTING)
            return retval;
        enclave_status = oe_fuzz_ecall(enclave, &retval, data, size);        
        return retval;
    }

  protected:
    oe_result_t enclave_status = OE_OK;
    oe_enclave_t *enclave = nullptr;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 512)
        return 0;
        
    std::unique_ptr<enclaveapi_fuzzer> fuzzer  = std::make_unique<enclaveapi_fuzzer>();

    int retval = 0;
    if (fuzzer)
        retval = fuzzer->fuzz(data, size);

    return retval;
}

extern "C" void LLVMFuzzerFinalize() {}
