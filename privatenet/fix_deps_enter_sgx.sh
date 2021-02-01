# (DCMMC) fix dependencies problem when enter sgx environment
# by scripts/sgx-enter.sh
# cat <<EOF > /etc/apt/sources.list
# deb http://mirrors.cloud.tencent.com/ubuntu/ xenial main restricted universe multiverse
# deb http://mirrors.cloud.tencent.com/ubuntu/ xenial-security main restricted universe multiverse
# deb http://mirrors.cloud.tencent.com/ubuntu/ xenial-updates main restricted universe multiverse
# EOF
# if [[ -d /code/privatenet/pkgs ]]
# then
#   dpkg -i /code/privatenet/pkgs/*.deb
# else
#   apt update && apt install -y libmicrohttpd-dev libjsoncpp-dev libjsonrpccpp-dev libjsonrpccpp-tools
# fi
cd /build
cmake -DCMAKE_INSTALL_PREFIX=/tc /code
make -j2 && make install && /tc/bin/tc-keygen --enclave /tc/enclave/enclave.debug.so --keygen /tmp/key.txt
sealed_key=`cat /tmp/key.txt`
cp -v /code/privatenet/config-privatenet-sim /tmp/tc_config
sed -i '8s:sig_key = .\+$:sig_key = '${sealed_key}':' /tmp/tc_config
echo 'New sealed_key: '${sealed_key}
