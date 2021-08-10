# Sample enclave fuzzer target

This is a sample target showing [host](host/host.cpp) and [enclave](enc/enc.cpp) to fuzz ECALL of an enclave. 

1. To implement a enclave target link [fuzzsupport](../fuzzsupport) library in your project which provides functions that are required for enclave libfuzzer.
2. Implement a class which derives from [oe_fuzzer_host](../common/oefuzzer.h)
3. Create and load the enclave in your constructor
4. Override the fuzz fucntion to invoke the target fucntion with approprioate payload data type casting.
