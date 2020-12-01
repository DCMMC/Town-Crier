# (DCMMC) fix dependencies problem when enter sgx environment
# by scripts/sgx-enter.sh
apt install -y libmicrohttpd-dev libjsoncpp-dev libjsonrpccpp-dev libjsonrpccpp-tools
cd /build
cmake -DCMAKE_INSTALL_PREFIX=/tc /code
make -j && make install
