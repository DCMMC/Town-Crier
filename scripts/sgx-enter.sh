#!/bin/bash

ROOTDIR=$( cd "$( dirname "${BASH_SOURCE[0]}")/.." && pwd )

tc_dev_image=bl4ck5un/tc-sgx-sdk
tc_dev_shell=bash

which docker >/dev/null || {
  echo "ERROR: Please install Docker first."
  exit 1
}

# Start SGX Rust Docker container.
# (DCMMC) 进入一个有 SGX SDL 和 SGX SSL 的环境，方便编译
docker run --rm -t -i \
  --name "tc-devel" \
  -v ${ROOTDIR}:/code \
  -e "SGX_SDK=/opt/intel/sgxsdk" \
  -p 8123:8123 \
  -w /build \
  "$tc_dev_image" \
  /usr/bin/env $tc_dev_shell
