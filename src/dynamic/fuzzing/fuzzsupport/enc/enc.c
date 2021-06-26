// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <stdint.h>
#include <stdlib.h>
#include "fuzzsupport_t.h"

#include "pthread.h"

__attribute__((visibility("default")))
uint64_t __sanitizer_get_host_tpc()
{
    uint64_t tpc = 0;
    oe_get_tpc_ocall(&tpc);
    return tpc;
}

__attribute__((visibility("default")))
void __asan_send_command_to_symbolizer(uint64_t module_offset, char** symbol)
{
    oe_get_symbol_ocall(oe_get_enclave(), module_offset, symbol);
}

__attribute__((visibility("default")))
void __sanitizer_die()
{
    oe_die_ocall();
}

void *__dlsym(void *restrict handle, const char *restrict name, void *restrict sym_addr)
{
    void* ret = NULL;
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(handle);
    OE_UNUSED(sym_addr);

    uint64_t offset = 0ULL;
    if (oe_get_symbol_offset_ocall(&result, oe_get_enclave(), name, &offset) != OE_OK)
        goto done;

    if (result != OE_OK)
        goto done;

    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();
    uint64_t* dest = (uint64_t*)(baseaddr + offset);

    ret = (void*)dest;

done:
    return ret;
}
