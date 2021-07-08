#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -e
ulimit -n 4096

export OE_SEC_ROOT=${PWD}
export OE_SEC_BUILD=${OE_SEC_ROOT}/build
export OE_SEC_TOOLS=${OE_SEC_ROOT}/build/tools
export OE_SRC_ROOT=${OE_SEC_ROOT}/sut/openenclave
export OE_3RDPARTY=${OE_SEC_ROOT}/3rdparty

export OE_UNINSTRUMENTED_BUILD=${OE_SEC_BUILD}/oe_uninstrumented_build
export OE_UNINSTRUMENTED_INSTALL_PREFIX=${OE_SEC_BUILD}/oe_uninstrumented_install_prefix
export OE_SEC_CORPUS_BUILD=${OE_SEC_BUILD}/corpus_build
export OE_SEC_ENCLAVE_CORPUS=${OE_SEC_ROOT}/src/dynamic/fuzzing/create/enclave_corpus

export OE_INSTRUMENTED_BUILD=${OE_SEC_BUILD}/oe_instrumented_build
export OE_INSTRUMENTED_INSTALL_PREFIX=${OE_SEC_BUILD}/oe_instrumented_install_prefix
export OE_SEC_FUZZING_BUILD=${OE_SEC_BUILD}/fuzzing_build

export OE_LLVM_URL="https://github.com/openenclave/openenclave-security/releases/download/v1.0/oe-llvm-1.0.zip"
export CLANG=${OE_SEC_TOOLS}/oe-llvm-1.0/bin/clang
export CLANG_CPP=${OE_SEC_TOOLS}/oe-llvm-1.0/bin/clang++

export INTEL_SGX_SDK="https://download.01.org/intel-sgx/sgx-linux/2.13/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.13.100.4.bin"
export INTEL_SGX_SDK_PACKAGE="sgx_linux_x64_sdk_2.13.100.4.bin"

CLEAN=0
INSTALL_DEPENDS=0
BUILD_INTEL_SGX_PSW=0
for i in "$@"; do
    case $i in
    -c | --clean)
        CLEAN=1
        ;;
    esac
    case $i in
    -d | --depends)
        INSTALL_DEPENDS=1
        ;;
    esac
    case $i in
    -i | --intelsdk)
        BUILD_INTEL_SGX_PSW=1
        ;;
    esac
done

# Intel PSW build dependencies
if [[ $INSTALL_DEPENDS -eq 1 ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget \
        libssl-dev perl libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper reprepro unzip
fi

[[ ${CLEAN} -eq 1 ]] && rm -rf "${OE_SEC_BUILD}"
[[ ! -d "${OE_SEC_BUILD}" ]] && mkdir -p "${OE_SEC_BUILD}"

if [[ ! -d "${OE_SEC_TOOLS}" ]]; then
    mkdir -p "${OE_SEC_TOOLS}"
    pushd "${OE_SEC_TOOLS}"
    wget "${OE_LLVM_URL}"
    unzip oe-llvm-1.0.zip
    popd
fi

MAKE_THREADS=$(nproc)

# Building debug version of Intel PSW.
if [[ ${BUILD_INTEL_SGX_PSW} -eq 1 ]]; then
    if [[ ! -d "/opt/intel/sgxsdk" ]]; then
        pushd "${OE_SEC_TOOLS}"
        wget "${INTEL_SGX_SDK}"
        chmod +x ./"${INTEL_SGX_SDK_PACKAGE}"
        sudo ./"${INTEL_SGX_SDK_PACKAGE}" <<EOF
no
/opt/intel
EOF
        popd
    fi

    pushd "${OE_3RDPARTY}"
    make -C linux-sgx clean all
    make -C linux-sgx preparation
    make -C linux-sgx psw DEBUG=1 -j ${MAKE_THREADS}
    popd
fi

# Building OE in release mode to build an enclave which will used as corpus data in create api fuzzing.
if [[ ! -d "${OE_UNINSTRUMENTED_BUILD}" ]]; then
    mkdir -p "${OE_UNINSTRUMENTED_BUILD}"
    mkdir -p "${OE_UNINSTRUMENTED_INSTALL_PREFIX}"
    pushd "${OE_UNINSTRUMENTED_BUILD}"
    cmake "${OE_SRC_ROOT}" -GNinja \
        -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER="${CLANG}" \
        -DCMAKE_CXX_COMPILER="${CLANG_CPP}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DUSE_DEBUG_MALLOC=OFF \
        -DCMAKE_INSTALL_PREFIX="${OE_UNINSTRUMENTED_INSTALL_PREFIX}"
    ninja install -j ${MAKE_THREADS}
    popd
fi

# Building OE in debug mode and instrumented with OE-LLVM sanitizers.
if [[ ! -d "${OE_INSTRUMENTED_BUILD}" ]]; then
    mkdir -p "${OE_INSTRUMENTED_BUILD}"
    mkdir -p "${OE_INSTRUMENTED_INSTALL_PREFIX}"
    pushd "${OE_INSTRUMENTED_BUILD}"
    cmake "${OE_SRC_ROOT}" -GNinja \
        -DENABLE_FUZZING=ON \
        -DBUILD_OEGENERATE_TOOL=OFF \
        -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER="${CLANG}" \
        -DCMAKE_CXX_COMPILER="${CLANG_CPP}" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS_DEBUG="-O0 -g" \
        -DCMAKE_CXX_FLAGS_DEBUG="-O0 -g" \
        -DUSE_DEBUG_MALLOC=OFF \
        -DCMAKE_INSTALL_PREFIX="${OE_INSTRUMENTED_INSTALL_PREFIX}"
    ninja install -j ${MAKE_THREADS}
    popd
fi

# Building an enclave with un-instrumented OE-SDK.
rm -rf "${OE_SEC_CORPUS_BUILD}"
mkdir -p "${OE_SEC_CORPUS_BUILD}"
pushd "${OE_SEC_CORPUS_BUILD}"
cmake "${OE_SEC_ENCLAVE_CORPUS}" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${CLANG}" \
    -DCMAKE_CXX_COMPILER="${CLANG_CPP}" \
    -DCMAKE_PREFIX_PATH="${OE_UNINSTRUMENTED_INSTALL_PREFIX}"
ninja -j ${MAKE_THREADS}
popd

# Building fuzzer targets with instrumented OE-SDK.
rm -rf "${OE_SEC_FUZZING_BUILD}"
mkdir -p "${OE_SEC_FUZZING_BUILD}"
pushd "${OE_SEC_FUZZING_BUILD}"
cmake "${OE_SEC_ROOT}" -GNinja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS_DEBUG="-O0 -g" \
    -DCMAKE_CXX_FLAGS_DEBUG="-O0 -g" \
    -DCMAKE_C_COMPILER="${CLANG}" \
    -DCMAKE_CXX_COMPILER="${CLANG_CPP}" \
    -DCMAKE_PREFIX_PATH="${OE_INSTRUMENTED_INSTALL_PREFIX}"
ninja -j ${MAKE_THREADS}
popd

# Prepare artificats needed for onefuzz.
pushd "${OE_SEC_FUZZING_BUILD}"/output/bin
cp ${OE_SEC_ROOT}/src/dynamic/scripts/onefuzz/setup.sh ./
cp "${OE_3RDPARTY}"/linux-sgx/build/linux/libsgx_enclave_common.so ./
mkdir create_corpus
cp "${OE_SEC_CORPUS_BUILD}"/output/bin/create_enclave.signed ./create_corpus/
popd
