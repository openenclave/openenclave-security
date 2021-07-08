#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
set -ex
ROOT_DIR=$(git rev-parse --show-toplevel)
AZCOPY_DIR="$ROOT_DIR/build/tools/azcopy"
FUZZING_BUILD="$ROOT_DIR/build/fuzzing_build/output/bin"
PROJECT="openenclave"
POOL="oefuzz-pool"
DURATION=1
GITHUB_ISSUES_NOTIFICATION="$ROOT_DIR/.github/workflows/github-issues.json"

[[ -d "$AZCOPY_DIR" ]] && rm -rf "$AZCOPY_DIR"
mkdir -p "$AZCOPY_DIR"
pushd "$AZCOPY_DIR"
wget -O azcopy.tgz https://aka.ms/downloadazcopy-v10-linux
tar zxvf azcopy.tgz
mv azcopy_linux_amd64*/* "$AZCOPY_DIR"
export AZCOPY="$AZCOPY_DIR/azcopy"
popd

pushd "$FUZZING_BUILD"
onefuzz template libfuzzer basic $PROJECT create $GITHUB_SHA $POOL \
    --target_exe ./create_host \
    --duration $DURATION \
    --setup_dir $FUZZING_BUILD \
    --inputs ./create_corpus \
    --notification_config @"$GITHUB_ISSUES_NOTIFICATION" \
    --colocate_all_tasks \
    --target_env ONEFUZZ_SETUP_DIR={setup_dir} LD_PRELOAD="{setup_dir}/libcreate_fileapihook.so"

List=(
    "oe_generate_attestation_certificate_enc_fuzz"
    "oe_get_private_key_by_policy_enc_fuzz"
    "oe_get_private_key_enc_fuzz"
    "oe_get_public_key_by_policy_enc_fuzz"
    "oe_get_public_key_by_policy_host_fuzz"
    "oe_get_public_key_enc_fuzz"
    'oe_get_public_key_host_fuzz'
    "oe_get_report_enc_fuzz"
    "oe_get_report_host_fuzz"
    "oe_get_seal_key_by_policy_enc_fuzz"
    "oe_get_seal_key_enc_fuzz"
    "oe_get_target_info_enc_fuzz"
    "oe_get_target_info_host_fuzz"
    "oe_parse_report_enc_fuzz"
    "oe_parse_report_host_fuzz"
    "oe_verify_attestation_certificate_enc_fuzz"
    "oe_verify_report_enc_fuzz"
    "oe_verify_report_host_fuzz"
)

for target in ${List[*]}; do
    onefuzz template libfuzzer basic $PROJECT $target $GITHUB_SHA $POOL \
        --target_exe ./$target \
        --duration $DURATION \
        --setup_dir $FUZZING_BUILD \
        --notification_config @"$GITHUB_ISSUES_NOTIFICATION" \
        --colocate_all_tasks \
        --target_env ONEFUZZ_SETUP_DIR={setup_dir}
done
popd
