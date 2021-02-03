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

# docker stop scone
# sleep 3s
# docker rm scone
# docker run --rm -td --net=host --name scone $MOUNT_SGXDEVICE -v "$PWD"/..:/code -w /code registry.scontain.com:5050/sconecuratedimages/crosscompilers:alpine
# docker exec -it scone bash -c 'sed -i "s/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g" /etc/apk/repositories && apk add python3 gcc python3-dev && pip3 install -i https://mirrors.bfsu.edu.cn/pypi/web/simple Flask mysql-connector-python grpcio==1.26.0 web3'

echo 'Run load_balancer and voting'
docker exec -td scone bash -c 'pkill python3'

docker exec -td scone bash -c 'cd /code/privatenet/ && python3 load_balancer.py >/code/privatenet/logs/load_balancer.log 2>&1'

docker exec -td scone bash -c 'cd /code/privatenet/ && python3 voting.py >/code/privatenet/logs/voting.log 2>&1'
