// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <bits/stdint-uintn.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdint.h>
#include <stdlib.h>
#include "openenclave/host/sgx/enclave.h"
#include "fuzzsupport_args.h"
#include "fuzzsupport_u.h"

#include <dlfcn.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <map>

uint64_t gtpc;
static elf64_t enclave_elf = ELF64_INIT;
static bool enclave_elf_loaded = false;

extern "C" void InitializeEnclaveFuzzer()
{
    typedef uint64_t (*fn__sanitizer_get_tpc)();
    fn__sanitizer_get_tpc fn =
        (fn__sanitizer_get_tpc)dlsym(RTLD_DEFAULT, "__sanitizer_get_tpc");
    if (fn)
        gtpc = (*fn)();
}

extern "C" void DestroyEnclaveFuzzer()
{
    if (enclave_elf_loaded)
    {
        elf64_unload(&enclave_elf);
        enclave_elf = ELF64_INIT;
        enclave_elf_loaded = false;
    }
}

uint64_t oe_get_tpc_ocall()
{
    return gtpc;
}

void oe_get_enclave_module_path_ocall(oe_enclave_t* oe_enclave, char* path)
{
    if (!oe_enclave || !oe_enclave->path)
        abort();

    strcpy(path, oe_enclave->path);
}

void oe_get_symbol_ocall(
    oe_enclave_t* oe_enclave,
    uint64_t module_offset,
    char** symbol)
{
    if (!oe_enclave || !oe_enclave->path)
        abort();

    typedef void (*fn__sanitizer_get_symbol)(char*, unsigned long long, char**);
    fn__sanitizer_get_symbol fn =
        (fn__sanitizer_get_symbol)dlsym(RTLD_DEFAULT, "__sanitizer_get_symbol");
    if (fn)
        fn(oe_enclave->path, module_offset, symbol);
}

void oe_die_ocall()
{
    typedef void (*fn__sanitizer_die)();
    fn__sanitizer_die fn =
        (fn__sanitizer_die)dlsym(RTLD_DEFAULT, "__sanitizer_die");
    if (fn)
        fn();
}

oe_result_t oe_get_symbol_offset_ocall(
    oe_enclave_t* oe_enclave,
    const char* name,
    uint64_t* offset)
{
    static std::map<std::string, uint64_t> sym_map;
    if (sym_map.empty())
    {
        if (!enclave_elf_loaded)
        {
            if (elf64_load(oe_enclave->path, &enclave_elf) != 0)
                return OE_UNEXPECTED;
            if (!enclave_elf.data)
                return OE_UNEXPECTED;
            enclave_elf_loaded = true;
        }
        
        size_t index = elf_find_shdr(&enclave_elf, ".symtab");
        const elf64_shdr_t* sh = elf64_get_section_header(&enclave_elf, index);
        if (!sh) return OE_UNEXPECTED;

        const elf64_sym_t* symtab = (const elf64_sym_t*)elf_get_section(&enclave_elf, index);
        if (!symtab) return OE_UNEXPECTED;

        size_t n = sh->sh_size / sh->sh_entsize;
        for (size_t i = 1; i < n; i++)
        {
            const elf64_sym_t* p = &symtab[i];
            if (!p || !p->st_name) continue;

            const char* s = elf64_get_string_from_strtab(&enclave_elf, p->st_name);
            if (!s) return OE_UNEXPECTED;
            
            sym_map.insert({s, (uint64_t)p->st_value});
        }
    }

    auto it = sym_map.find(name);
    if (it != sym_map.end())
        *offset = it->second;

    return (*offset) ? OE_OK : OE_UNEXPECTED;
}

oe_result_t oe_syscall_ocall(
    uint64_t syscall_id,
    uint64_t* return_value,
    void* args)
{
    switch (syscall_id)
    {
        case OE_OCALL_PRRLIMIT64:
        {
            struct prlimit64_args* arg_ptr = (struct prlimit64_args*)args;
            *return_value = (uint64_t)syscall(
                SYS_prlimit64,
                arg_ptr->pid,
                arg_ptr->resource,
                arg_ptr->new_limit,
                arg_ptr->old_limit);
        }
        break;
        case OE_OCALL_GETLIMIT:
        {
            struct getrlimit_args* arg_ptr = (struct getrlimit_args*)args;
            *return_value = (uint64_t)syscall(
                SYS_getrlimit, arg_ptr->resource, arg_ptr->rlim);
        }
        break;
    }

    return OE_OK;
}
