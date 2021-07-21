// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#include <algorithm>
#include <cassert>
#include <iostream>
#include <vector>
#include <limits.h>
#include <unistd.h>

extern "C" void InitializeEnclaveFuzzer();
extern "C" void DestroyEnclaveFuzzer();

class non_copyable
{
  public:
    non_copyable() = default;
    virtual ~non_copyable() = default;
    non_copyable(const non_copyable &) = delete;
    void operator=(const non_copyable &) = delete;
};

class oe_fuzzer_host : public non_copyable
{
  public:
    oe_fuzzer_host()
    {
        InitializeEnclaveFuzzer();
    }

    virtual ~oe_fuzzer_host()
    {
        DestroyEnclaveFuzzer();
    }

    virtual int fuzz(const uint8_t *data, size_t size) = 0;
    inline bool get_proc_path(std::string &path)
    {
        std::vector<char> proc_path(PATH_MAX);
        if (readlink("/proc/self/exe", proc_path.data(), PATH_MAX - 1) == -1)
            return false;
        std::string proc_dir(proc_path.begin(), proc_path.end());
        path = proc_dir.substr(0, proc_dir.rfind("/"));
        return true;
    }
};

class oe_fuzzer_enclave: public non_copyable
{
public:
    oe_fuzzer_enclave() = default;
    virtual ~oe_fuzzer_enclave() = default;
    virtual int fuzz(const uint8_t *data, size_t size) = 0;
};
