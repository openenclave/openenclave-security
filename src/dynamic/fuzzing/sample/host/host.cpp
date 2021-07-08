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
#include "enclavefuzz_u.h"

class enclaveapi_fuzzer : public oe_fuzzer_host
{
  public:
    enclaveapi_fuzzer()
    {
        std::string enc_path;
        if (get_proc_path(enc_path))
        {
            enc_path.append("/enclavefuzz_enc");
        }

        assert(!access(enc_path.c_str(), F_OK));
        uint32_t flags = oe_get_create_flags();
        oe_result_t result = oe_create_enclavefuzz_enclave(enc_path.c_str(), OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (result != OE_OK)
        {
            oe_put_err("Failed to create encalve, result=%u", result);
        }
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

std::unique_ptr<enclaveapi_fuzzer> fuzzer;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!fuzzer)
        fuzzer = std::make_unique<enclaveapi_fuzzer>();

    int retval = 0;
    if (fuzzer)
        retval = fuzzer->fuzz(data, size);

    return retval;
}

extern "C" void LLVMFuzzerFinalize()
{   
    fuzzer.reset();
}
