#!/bin/bash
function determine_sgx_device {
    export SGXDEVICE="/dev/sgx"
    export MOUNT_SGXDEVICE="-v /dev/sgx/:/dev/sgx"
    if [[ ! -e "$SGXDEVICE" ]] ; then
        export SGXDEVICE="/dev/isgx"
        export MOUNT_SGXDEVICE="--device=/dev/isgx"
        if [[ ! -c "$SGXDEVICE" ]] ; then
            echo "Warning: No SGX device found! Will run in SIM mode." > /dev/stderr
            export MOUNT_SGXDEVICE=""
            export SGXDEVICE=""
        fi
    fi
}

determine_sgx_device

# ref: https://sconedocs.github.io/registry/
# user: DCMMCC
# token: generate from https://gitlab.scontain.com/-/profile/personal_access_tokens with read_registry permission
# docker login registry.scontain.com:5050

docker run --rm -td $MOUNT_SGXDEVICE -v "$PWD"/..:/code -w /code -p 8000:8000 registry.scontain.com:5050/sconecuratedimages/crosscompilers:alpine
