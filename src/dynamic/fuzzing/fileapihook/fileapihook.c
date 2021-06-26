// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef void FILE;
typedef FILE *(*orig_fopen)(const char *__filename, const char *__modes);
typedef size_t (*orig_fread)(void *ptr, size_t size, size_t nitems, FILE *stream);
typedef int (*orig_fileno)(FILE *__stream);
typedef int (*orig_fstat)(int __fd, struct stat *__buf);
typedef int (*orig_fstat64)(int __fd, struct stat64 *__buf);
typedef int (*orig___fxstat)(int ver, int fildes, struct stat64 *stat_buf);
typedef int (*orig_fclose)(FILE *__stream);
typedef int (*orig_fseek)(FILE *stream, long offset, int whence);
typedef long (*orig_ftell)(FILE *stream);

struct __sanitizer_FILE
{
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    void *_markers;
    struct __sanitizer_FILE *_chain;
    int _fileno;
};

static const uint8_t *enc = NULL;
static size_t enc_size;
static struct __sanitizer_FILE file_handle = {0};
static long enclave_file_handle = (long)(&file_handle);
// static int enclave_file_handle = 0xFEEDF00D;
static int enc_fd = 0x12345678;
static struct stat enc_stat;
static struct stat64 enc_stat64;
static int current_whence = SEEK_SET;
static long current_offset = 0;

char kHookFilePath[] = "/tmp/2de32e3b-9225-4be9-a7b7-56b2e73c4448";
__attribute__((visibility("default"))) void init_file_hook(const uint8_t *data, size_t size)
{
    enc = data;
    enc_size = size;
}

FILE *fopen(const char *__filename, const char *__modes)
{
    if (strcmp(__filename, kHookFilePath) == 0)
    {
        return (FILE *)enclave_file_handle;
    }

    static orig_fopen fn = NULL;
    if (!fn)
        fn = (orig_fopen)dlsym(RTLD_NEXT, "fopen");
    return fn(__filename, __modes);
}

size_t fread(void *ptr, size_t size, size_t nitems, FILE *stream)
{
    if ((long)stream == enclave_file_handle)
    {
        memcpy(ptr, enc, nitems);
        return nitems;
    }

    static orig_fread fn = NULL;
    if (!fn)
        fn = (orig_fread)dlsym(RTLD_NEXT, "fread");
    return fn(ptr, size, nitems, stream);
}

int fileno(FILE *__stream)
{
    if ((long)__stream == enclave_file_handle)
    {
        return enc_fd;
    }

    static orig_fileno fn = NULL;
    if (!fn)
        fn = (orig_fileno)dlsym(RTLD_NEXT, "fileno");
    return fn(__stream);
}

int __fxstat(int ver, int fildes, struct stat64 *stat_buf)
{
    if (fildes == enc_fd)
    {
        stat_buf->st_mode = __S_IFREG;
        stat_buf->st_size = enc_size;
        return 0;
    }

    static orig___fxstat fn = NULL;
    if (!fn)
        fn = (orig___fxstat)dlsym(RTLD_NEXT, "__fxstat");
    return fn(ver, fildes, stat_buf);
}

int fstat(int __fd, struct stat *__buf)
{
    if (__fd == enc_fd)
    {
        enc_stat.st_mode = __S_IFREG;
        enc_stat.st_size = enc_size;
        __buf = &enc_stat;
        return 0;
    }

    static orig_fstat fn = NULL;
    if (!fn)
        fn = (orig_fstat)dlsym(RTLD_NEXT, "fstat");
    return fn(__fd, __buf);
}

int fstat64(int __fd, struct stat64 *__buf)
{
    if (__fd == enc_fd)
    {
        enc_stat64.st_mode = __S_IFREG;
        enc_stat64.st_size = enc_size;
        __buf = &enc_stat64;
        return 0;
    }

    static orig_fstat64 fn = NULL;
    if (!fn)
        fn = (orig_fstat64)dlsym(RTLD_NEXT, "fstat64");
    return fn(__fd, __buf);
}

int fclose(FILE *__stream)
{
    if ((long)__stream == enclave_file_handle)
    {
        return 0;
    }

    static orig_fclose fn = NULL;
    if (!fn)
        fn = (orig_fclose)dlsym(RTLD_NEXT, "fclose");
    return fn(__stream);
}

int fseek(FILE *stream, long offset, int whence)
{
    if ((long)stream == enclave_file_handle)
    {
        current_whence = whence;
        current_offset = offset;
        return 0;
    }

    static orig_fseek fn = NULL;
    if (!fn)
        fn = (orig_fseek)dlsym(RTLD_NEXT, "fseek");
    return fn(stream, offset, whence);
}

long ftell(FILE *stream)
{
    if ((long)stream == enclave_file_handle)
    {
        if (current_whence == SEEK_SET)
            return 0;
        else if (current_whence == SEEK_CUR)
            return current_offset;
        else if (current_whence == SEEK_END)
            return (enc_size > 0 && current_offset >= 0 && current_offset <= enc_size) ? enc_size - current_offset : 0;
        return 0;
    }

    static orig_ftell fn = NULL;
    if (!fn)
        fn = (orig_ftell)dlsym(RTLD_NEXT, "ftell");
    return fn(stream);
}
