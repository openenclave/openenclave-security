# Fuzzing Open Enclave API

This project contains fuzzer support library and libfuzzer based target programs to fuzz Open Enclave APIs exposed in [host](https://github.com/openenclave/openenclave/blob/master/include/openenclave/host.h) and [enclave](https://github.com/openenclave/openenclave/blob/master/include/openenclave/enclave.h). Open Enclave fuzzer targets are built using customized LLVM toolchain to enable fuzzing on enclave binaries.

## OneFuzz CI/CD Integration
Open Enclave fuzzing infrastructure is an instance of OneFuzz service hosted on Azure DCs series virtual machine scalesets. Onefuzz [workflow](../../../.github/workflows/onefuzz-workflow.yml) is scheduled to [run](../../../src/dynamic/scripts/onefuzz/run.sh) on nightly basis which creates onefuzz job templates and uploads fuzzing artifiacts. Onefuzz instance is configured with an array of SGX virtual machines which are dispatched to run the fuzzer targets and managed by VM scalesets. 

**References**
* [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
* [Address Sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
* [OneFuzz](https://github.com/microsoft/onefuzz)
