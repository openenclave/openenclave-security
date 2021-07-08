// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "create_u.h"
#include "elf.h"
#include <bits/stdint-uintn.h>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <dlfcn.h>
#include <memory>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <vector>
#include <fstream>

const char kLibFileApiHook[] = "libcreate_fileapihook.so";
const char kInitFileHook[] = "init_file_hook";
const char kMockEnclavePath[] = "/tmp/2de32e3b-9225-4be9-a7b7-56b2e73c4448";

int CreateEnclave(const char *enclave_path)
{
    oe_result_t result = OE_UNEXPECTED;
    int ret = -1;
    oe_enclave_t *enclave = NULL;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    result = oe_create_create_enclave(enclave_path, OE_ENCLAVE_TYPE_SGX, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        goto exit;
    }

    fprintf(stderr, "Enclave Created Succesfully!\n");
    ret = 0;
exit:
    if (enclave)
    {
        oe_terminate_enclave(enclave);
    }

    return ret;
}

void *handle = NULL;
typedef void (*fn_init_file_hook)(const uint8_t *data, size_t size);
fn_init_file_hook init_file_hook = NULL;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 64)
    {
        if (handle == NULL)
        {
            std::ofstream enc;
            enc.open(kMockEnclavePath, std::ios::app);
            handle = dlopen(kLibFileApiHook, RTLD_LOCAL | RTLD_LAZY);
            if (handle)
            {
                init_file_hook = (fn_init_file_hook)dlsym(handle, kInitFileHook);
            }
        }

        if (init_file_hook)
        {
            elf64_ehdr_t *hdr = (elf64_ehdr_t *)data;
            if (elf64_test_header(hdr) < 0)
                return 0;

            uint64_t elf_size = (uint64_t)hdr->e_phentsize * hdr->e_phnum;
            uint64_t end = hdr->e_phoff + elf_size;
            if (size < end)
                return 0;

            elf_size = (uint64_t)hdr->e_shentsize * hdr->e_shnum;
            end = hdr->e_shoff + elf_size;
            if (size < end)
                return 0;

            (*init_file_hook)(data, size);
            (void)CreateEnclave(kMockEnclavePath);
        }
    }

    return 0;
}

extern "C" void LLVMFuzzerFinalize()
{
    if (handle)
    {
        dlclose(handle);
        handle = NULL;
    }
}
