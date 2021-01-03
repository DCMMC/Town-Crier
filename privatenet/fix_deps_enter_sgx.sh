# (DCMMC) fix dependencies problem when enter sgx environment
# by scripts/sgx-enter.sh
if [[ -d /code/privatenet/pkgs ]]
then
  dpkg -i /code/privatenet/pkgs/*.deb
else
  apt install -y libmicrohttpd-dev libjsoncpp-dev libjsonrpccpp-dev libjsonrpccpp-tools
fi
cd /build
cmake -DCMAKE_INSTALL_PREFIX=/tc /code
make -j && make install && /tc/bin/tc-keygen --enclave /tc/enclave/enclave.debug.so --keygen /tmp/key.txt
sealed_key=`cat /tmp/key.txt`
sed -i '8s:sig_key = .\+$:sig_key = '${sealed_key}':' /code/privatenet/config-privatenet-sim
echo 'New sealed_key: '${sealed_key}
