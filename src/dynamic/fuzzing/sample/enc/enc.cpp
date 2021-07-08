// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>

#include "openenclave/include/openenclave/enclave.h"
#include "openenclave/include/openenclave/internal/raise.h"
#include "openenclave/include/openenclave/internal/trace.h"
#include "openenclave/include/openenclave/corelibc/stdlib.h"

#include "enclavefuzz_t.h"
#include "oefuzzer.h"

OE_SET_ENCLAVE_SGX(1,     /* ProductID */
                   1,     /* SecurityVersion */
                   true,  /* Debug */
                   25600, /* NumHeapPages */
                   2048,  /* NumStackPages */
                   1);    /* NumTCS */

void do_heapoverflow()
{
    size_t size = 32;
    char *arr = (char*)oe_malloc(size);
    arr[size] = 'X';
    oe_free(arr);
}

// __attribute__((no_sanitize("enclaveaddress")))
void do_stack_use_after_scope()
{
    int *ptr = NULL;
    {
        int var = 10;
        ptr = &var;
        *ptr = 100;
    }
    *ptr = 200;
}

void do_use_after_free()
{
    size_t size = 8;
    char *arr = (char*)oe_malloc(size);
    arr[0] = 'X';
    oe_free(arr);
    arr[0] = 'X';
}

void do_double_free()
{
    size_t size = 8;
    char *arr = (char*)oe_malloc(size);
    arr[0] = 'X';
    oe_free(arr);
    oe_free(arr);
}


class oe_get_report_fuzz : public oe_fuzzer_enclave
{
  public:
    int fuzz(const uint8_t *data, size_t size)
    {
        do_heapoverflow();
        return OE_OK;
    }
};

std::unique_ptr<oe_fuzzer_enclave> fuzzer;
int oe_fuzz_ecall(const uint8_t *data, size_t size)
{
    if (!fuzzer)
        fuzzer = std::make_unique<oe_get_report_fuzz>();

    int retval = 0;
    if (fuzzer)
        retval = fuzzer->fuzz(data, size);

    return retval;
}

void oe_fuzz_cleanup_ecall()
{
    fuzzer.reset();
}
