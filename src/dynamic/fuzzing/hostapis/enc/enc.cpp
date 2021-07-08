// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openenclave/include/openenclave/enclave.h"
#include "openenclave/include/openenclave/internal/trace.h"
#include "hostapis_t.h"

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    25600, /* NumHeapPages */ // 100 MB
    1024, /* NumStackPages */
    2);   /* NumTCS */
