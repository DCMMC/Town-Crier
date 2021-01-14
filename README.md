# Town Crier: An Authenticated Data Feed For Smart Contracts

## Requirements

* Linux (macOS might work)
* Docker
* CPU with SGX support
* pip: py-solc, web3, grpcio
* nodejs: ethereumjs-wallet 0.6.5
* solc compiler 0.5.16 (build from source)
* geth

MySQL

```
docker run -d --name mysql --rm -e MYSQL_ROOT_PASSWORD=97294597 -v `pwd`/privatenet/mysql_keys/conf:/etc/mysql/conf.d -v `pwd`/privatenet/mysql_keys/cert:/etc/mysql/cert -p 3306:3306 mysql:5.7
```

SSL 密钥文件可以由 mysql 容器中的 `mysql_ssl_rsa_setup --datadir mysql_keys` 生成

test mysql over ssl in sgx:

```bash
cmake -DCMAKE_INSTALL_PREFIX=/tc /code && make -j && make install && /tc/bin/tc-keygen --enclave /tc/enclave/enclave.debug.so --keygen /tmp/key.txt && source /opt/intel/sgxsdk/environment && /tc/bin/tc --debug_mysql -c /code/privatenet/config-privatenet-sim | tee /tmp/debug.txt
```

## Build and run instructions

```
cd privatenet && bash setup_run.sh
```

LICENSE
-------

The permission granted herein is solely for the purpose of compiling the TownCrier source code.
See the LICENSE file for details.
