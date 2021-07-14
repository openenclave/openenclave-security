# Best Practices for Keeping Enclaves Secure
Use this guide to apply secure patterns and avoid common mistakes that put the security of your enclave applications at risk.

1.  [Best Practices for Interface Custom Marshaling ](#best-practices-for-interface-custom-marshaling)

2.  [Handling Secrets in Enclave Applications](#handling-secrets-in-enclave-applications)

<br />
<br />
<br />

# Best Practices for Interface Custom Marshaling 
(For an overview of using the Enclave Definition Language (EDL) and the oeedger8r tool to produce enclave interface code, please refer to [Getting started with the Open Enclave edger8r](Edger8rGettingStarted.md).)

Calling into and out of enclaves is done through special methods that switch into and out of the enclave, along with the marshaling of parameters that are passed into these functions. A lot of the code necessary to handle these calls and parameter marshaling are common to all function calls. Marshaling parameters from the host to the enclave for security purposed, and in doing so also helps to mitigate certain processor vulnerabilities (like spectre). The Open Enclave edger8r helps to define these special functions through the use of edl files and then generates boilerplate code for you.

In some uncommon cases, developers may want to pass data types that are not defined at the interface level or handle marshaling differently than the oeedger8r tool generates. This is done by specifying `user_check` for the parameter constraint like the following example:

```c++
enclave{
    trusted {
        public void ecall_with_user_check(
            [user_check] void* blob);
    };
};
```
In this simplified EDL example, the function takes one pointer-to-void parameter. Remember that the primary benefit of using supported types in the EDL is that the generated boiler-plate code performs the necessary and secure marshaling for the developer. When you specify that a parameter is `user_check`, you are signaling to oeedger8r that your application code is going to perform the marshaling. (Two examples of when custom marshaling is helpful are 1) when data formats are dynamic, and 2) when sharing large blocks of memory -- custom marshaling avoids the boiler-plate code's intermediate copying of data into safe in-enclave buffers.) 

> We'd like to stress that a secure best practice for enclave interfaces is to _avoid_ custom marshaling. But we understand that there may be cases where avoiding it is impractical, so in these sections we will help you do it safely.

The ecall function implementation below has several problems. We will be correcting this code as we move through the material. The general impetus for custom marshaling in this sample code is to avoid expensive intermediate copying of shared memory introduced by the oeedger8r's generated code. (Data passed to `render_data()` is "flat", that is, the data format is non-referential and thus non-_self_-referencing. These attributes reduce threats to enclaves from untrusted data streams. More on this in the following sections.)

```c++
typedef struct _blob {
    void* data;
    size_t size;
} blob_t;

// WARNING: Portions of this code are intentionally flawed to demonstrate common pitfalls.
int ecall_with_user_check0(void* ptr) {

    blob_t* blob;

    if (ptr == nullptr)
        return -1;

    blob = (blob_t*)ptr;

    if (blob->size > 4096)
        return -1;

    return render_data(blob->data, blob->size);
}
```

## Ensuring memory is where it should be

Remember that the code we are focused on is running _inside_ of the enclave. The host caller invoked this function from _outside_ the enclave, passing in a pointer value, ostensibly to host memory containing well-formed data. But in the Open Enclave security model, the host caller is untrusted - we must treat untrusted input with caution. 

One important security check is to ensure that memory blocks are on the correct side of the security boundary. It's common for host applications to pass host memory blocks to the enclave, as is the case with this example code.

Let's update the code to ensure the memory block is located _strictly_ outside the secured enclave memory region before operating on it.

```diff
// WARNING: Portions of this code are intentionally flawed to demonstrate common pitfalls.
int ecall_with_user_check1(void* ptr) {

    blob_t* blob;

-   if (ptr == nullptr)
-       return -1;
+   // Ensure passed-in pointer is not null and the memory block is located entirely outside of the enclave.
+   if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
+       return -1;

    blob = (blob_t*)ptr;

    if (blob->size > 4096)
        return -1;

    return render_data(blob->data, blob->size);
}
```
## oe_is_within_enclave() != !oe_is_outside_enclave()

Let's highlight a logical mistake that we've seen made. Some have regarded the memory validation functions as boolean opposites of each other, that is: `oe_is_within_enclave() == !oe_is_outside_enclave()`. This is incorrect for several reasons.

To understand why this function pair are _not_ boolean opposites, it helps to consider the SGX implementation: [memory.c](https://github.com/openenclave/openenclave/blob/08ebe60c1d2e3ea24ac634c673a420296bff3352/enclave/core/sgx/memory.c). There are three conditions that the functions validate:
1)	The pointer is not null.
2)	The bounding arithmetic operations do not wrap (i.e. numerical overflow).
3)	The block lies completely within or outside of the enclave.

The first two conditions should make clear the pitfalls of considering the function pair to be boolean opposites: If the pointer is null or the bounding calculations overflow in a call to `oe_is_within_enclave()`, the function will return `false`, which should _not_ be interpreted as "the memory is outside the enclave". 

The last condition is subtle: In some potentially malicious cases, the memory range may be both partially within and partially outside the enclave, spanning the boundary between the two. (Attacks against enclaves may use memory confusion to achieve overwrites of protected regions, for example.) Both functions will return `false` when the memory range spans the boundary - another reason the function pair are not boolean opposites.

<br />
<br />
<br />

## Time-of-check/Time-of-use or "double-fetch" vulnerabilities

One class of vulnerabilities that your marshaling code should protect against is referred to as time-of-check/time-of-use, or TOCTOU. Another name for this problem is "double-fetch". The problem arises when memory is shared across privilege boundaries. As code validates input, it's critical that data is not fetched twice (or, strictly, more than once), allowing a malicious untrusted called to change the data between the time-of-check and the time-of-use. Let's examine our function:

```c++
// WARNING: Portions of this code are intentionally flawed to demonstrate common pitfalls.
int ecall_with_user_check2(void* ptr) {

    blob_t* blob;

    // Ensure passed-in pointer is not null and the memory block is located entirely outside of the enclave.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

    if (blob->size > 4096) //TOCTOU: First fetch
        return -1;

    return render_data(blob->data, blob->size); //TOCTOU: Second fetch
}
```
There's nothing wrong with the first fetch: The value is validated, and the appropriate logic branch is taken. The problem arises when the code needs the value again and reads it, once again, from the untrusted memory location outside of the enclave. Between the first and subsequent fetch the value may have been changed, neutralizing the size validation and possibly leading to some enclave memory corruption that is helpful to the attacker. Let's protect the code by "capturing" the values.

> When "capturing" data values in this context, it's important to protect against the compiler's optimization, hence we use the `volatile` qualifier for our local blob_t. Otherwise, the compiler might optimize-away our local variable, removing the TOCTOU protection.

```diff
// WARNING: Portions of this code are intentionally flawed to demonstrate common pitfalls.
int ecall_with_user_check3(void* ptr) {

    blob_t* blob;
+   blob_t volatile captured_blob;

    // Ensure passed-in pointer is not null and the memory block is located entirely outside of the enclave.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

+   // Capture blob descriptors to avoid TOCTOU problems.
+   captured_blob.data = blob->data;
+   captured_blob.size = blob->size;

-   if (blob->size > 4096) //TOCTOU: First fetch
+   if (captured_blob.size > 4096)
        return -1;

-   return render_data(blob->data, blob->size); //TOCTOU: Second fetch
+   return render_data(captured_blob.data, captured_blob.size);
}
```

## Ensure proper bounding of data buffers

Another element of marshaling code is ensuring, as complex structures are parsed, that nested structures are also within the outer bounds. This is especially important for internal functions like `render_data()` that may be unaware that the memory is untrusted. Use the same techniques on the inner structures that were used on the outer.

> A warning about legacy data-parsers: Take care when passing "hot" data to code that may not have been written to parse maliciously crafted input. We have seen cases where legacy code that parses self-formatting or self-refencing data was used in new enclave applications. This can lead to significant vulnerabilities if the data being parsed is still controlled by the host, as may be the case with custom marshaling. In the case of this sample code, as mentioned earlier, `render_data()` parses "flat" data that is not nested nor self-referencing, so it's safe (and performant) to pass it "hot" data that is controlled by the host. Care must still be taken though, to avoid data-consistency and other app-level integrity problems.

```diff
int ecall_with_user_check4(void* ptr) {

    blob_t* blob;
    blob_t volatile captured_blob;

    // Ensure passed-in pointer is not null and the memory block is located entirely outside of the enclave.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

    // Capture blob descriptors to avoid TOCTOU problems.
    captured_blob.data = blob->data;
    captured_blob.size = blob->size;

    if (captured_blob.size > 4096)
        return -1;

+   // Ensure validity of nested structure
+   if (!oe_is_outside_enclave(captured_blob.data, captured_blob.size))
+       return -1;

+   // Data parsed by render_data is "flat", non-self-referencing.
    return render_data(captured_blob.data, captured_blob.size);
}
```
## Our secure enclave function

Thanks for sticking with us. Here is our corrected function:
```c++
int ecall_with_user_check5(void* ptr) {

    blob_t* blob;
    blob_t volatile captured_blob;

    // Ensure passed-in pointer is not null and the memory block is located entirely outside of the enclave.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

    // Capture blob descriptors to avoid TOCTOU problems.
    captured_blob.data = blob->data;
    captured_blob.size = blob->size;

    if (captured_blob.size > 4096)
        return -1;

    // Ensure validity of nested structure.
    if (!oe_is_outside_enclave(captured_blob.data, captured_blob.size))
        return -1;

    // Data parsed by render_data is "flat", non-self-referencing.
    return render_data(captured_blob.data, captured_blob.size);
}

```

<br />
<br />
<br />

# Handling Secrets in Enclave Applications

Open Enclave is an SDK that helps developers build apps that will run inside a hardware-based Trusted Execution Environment (TEE). At their core, TEEs protect application code and data at runtime from the host environment. Without new, hardware-implemented protections, a malicious or compromised host operating system would be able to modify code or read data. Any secrets managed by an application during runtime would be at risk of exposure. Open Enclave SDK helps developers build applications that are protected from these threats.

Enclaves provide new trust boundary protections that address old threats and open new capabilities. But just as Open Enclave and TEEs shift the security model, application developers must shift how they handle data, especially secrets, like keys and passwords.
<br />
<br />
<br />
## How __Not__ to Handle Application Secrets
Let's remind ourselves of a way _not_ to handle application secrets. A common example of this well-discussed application weakness is described by `TODO` CWE - CWE-798: Use of Hard-coded Credentials (4.4) (mitre.org). While application security is often a tradeoff between multiple factors and broad edicts are not always appropriate, it's not controversial to simply say that hard-coding credentials in application code _should not be done_.
<br />
<br />
<br />
## The New, Secure Enclave Way to Handle Application Secrets

Enclaves provide two properties that enable applications to handle secrets securely: 1) strong identity, 2) runtime protection of secrets in memory.

`TODO: This material should (already) exist in core Open Enclave documentation. Once the Open Enclave documentation is reorganized and complete, this best security practices section and link to relevant data.`



