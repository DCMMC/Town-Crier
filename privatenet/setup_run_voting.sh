#!/bin/bash
# (DCMMC) This script is highly experimental!
# Errors will happen during executing. If you encouter error,
# please carefully check all `sed ...` statements.
cat << EOF
This script is highly experimental!
Errors will happen during executing.
If you encouter error, please carefully check all 'sed ...' statements.
EOF
read -p "Do you want to continue? (Y/N)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
  echo 'Goodbye~'
  exit 0
fi

# fix sed in macOS
# [ref] https://blog.keniver.com/2018/05/mac-%E4%B8%8B%E5%9F%B7%E8%A1%8C-sed-%E6%8C%87%E4%BB%A4%E5%87%BA%E7%8F%BE%E9%8C%AF%E8%AA%A4-invalid-command-code-w/
sed_s () {
  case "$(uname -s)" in
    Darwin)
      sed -i "" "$@"
      ;;
    Linux)
      sed -i "$@"
      ;;
    *)
      ;;
  esac
}

echo 'Removing old accounts'
sudo pkill geth
sudo rm -rf node0{1,2,3}

echo 'Generate and initialize new accounts'
mkdir node0{1,2,3}
passwd='97294597'
geth --datadir node01 account new --password <(echo $passwd)
geth --datadir node02 account new --password <(echo $passwd)
geth --datadir node03 account new --password <(echo $passwd)

addr01=`geth account list --datadir node01 2>/dev/null | cut -d ' ' -f 3 | cut -b 2-41`
addr02=`geth account list --datadir node02 2>/dev/null | cut -d ' ' -f 3 | cut -b 2-41`
addr03=`geth account list --datadir node03 2>/dev/null | cut -d ' ' -f 3 | cut -b 2-41`

if [[ ${#addr01} != 40 ]]; then
  echo 'Wrong addr'
  exit -1
fi
if [[ ${#addr02} != 40 ]]; then
  echo 'Wrong addr'
  exit -1
fi
if [[ ${#addr03} != 40 ]]; then
  echo 'Wrong addr'
  exit -1
fi
sed_s '15s/\("0x\)[0-9a-fA-F]\{40\}/"0x'${addr01}'/' genesis.json
sed_s '15s/\("0x\)[0-9a-fA-F]\{40\}/"0x'${addr02}'/' genesis.json
sed_s '15s/\("0x\)[0-9a-fA-F]\{40\}/"0x'${addr03}'/' genesis.json
echo 'Modify genesis.json done.'

echo 'init and start runing nodes.'
geth --datadir node01 init genesis.json
geth --datadir node02 init genesis.json
geth --datadir node03 init genesis.json
echo 'Start running node01, node02, node03'
nohup geth --identity node01 --rpc --rpcport "8000" --rpccorsdomain '*' --datadir node01 --port "30303" --nodiscover --rpcapi "eth,net,web3,personal,miner,admin,debug" --networkid 1900 --nat "any" --allow-insecure-unlock --ethstats node01:s3cr3t@localhost:3000 >./logs/node01.log 2>&1 &
nohup geth --identity node02 --rpc --rpcport "8001" --rpccorsdomain '*' --datadir node02 --port "30313" --nodiscover --rpcapi "eth,net,web3,personal,miner,admin,debug" --networkid 1900 --nat "any" --allow-insecure-unlock --ethstats node02:s3cr3t@localhost:3000 >./logs/node02.log 2>&1 &
nohup geth --identity node03 --rpc --rpcport "8002" --rpccorsdomain '*' --datadir node03 --port "30323" --nodiscover --rpcapi "eth,net,web3,personal,miner,admin,debug" --vmdebug --networkid 1900 --nat "any" --allow-insecure-unlock --ethstats node03:s3cr3t@localhost:3000 >./logs/node03.log 2>&1 &
echo 'unlock accounts.'
sleep 2s
geth attach http://localhost:8000 --exec 'personal.unlockAccount(eth.accounts[0], "97294597", 36000)'
geth attach http://localhost:8001 --exec 'personal.unlockAccount(eth.accounts[0], "97294597", 36000)'
geth attach http://localhost:8002 --exec 'personal.unlockAccount(eth.accounts[0], "97294597", 36000)'
echo 'add peers.'
adminNode=`geth attach http://localhost:8000 --exec 'admin.nodeInfo.enode'`
geth attach http://localhost:8001 --exec "admin.addPeer("${adminNode}")"
geth attach http://localhost:8002 --exec "admin.addPeer("${adminNode}")"
echo 'Nodes done.'

sgx_wallet=`printf 'node01\n'${passwd}'\n' | node get_secret_key_from_keystore.js`
if [[ ${#sgx_wallet} != 64 ]]; then
  echo 'Wrong sgx_wallet'
  exit -1
fi
sed_s '102s/"[0-9a-fA-F]\{64\}/"'${sgx_wallet}'/' ../src/Enclave/eth_ecdsa.cpp
echo 'Updated source code of TC to new sgx_wallet: '${sgx_wallet}

echo 'start miner'
geth attach http://localhost:8000 --exec "miner.start(2)"
sleep 6s

echo 'Deploy and run App and TC contracts.'
add_sgx=`geth attach http://localhost:8000 --exec "web3.toChecksumAddress(eth.accounts[0])"`
# remove quota
add_sgx=${add_sgx:1:42}
echo 'Address of SGX wallet: '${add_sgx}
echo 'Address of SGX wallet: '${add_sgx} > address_info.txt
if [[ ${#add_sgx} != 42 ]]; then
  echo 'Wrong add_sgx'
  exit -1
fi
sed_s '23s/0x.\{40\};/'${add_sgx}';/' ./contracts/TownCrier.sol
# may encounter insufficient funds error in low-end devices...
# one workaround is to sleep...
sleep 20s
test_tc_res=`python3 test_tc.py`
echo ${test_tc_res}
add_tc=`echo ${test_tc_res} | cut -d ' ' -f 2`
add_app=`echo ${test_tc_res} | cut -d ' ' -f 4`
echo 'Address of TC: '${add_tc}
echo 'Address of TC: '${add_tc} >> address_info.txt
echo 'Address of APP: '${add_app}
echo 'Address of APP: '${add_app} >> address_info.txt
if [[ ${#add_tc} != 42 ]]; then
  echo 'Wrong add_tc'
  exit -1
fi
sed_s '2s/tc_address = .\{42\}$/tc_address = '${add_tc}'/' config-privatenet-sim
echo 'Modify tc_address in config-privatenet-sim'

echo 'Enter sgx env and run TC server'
ROOTDIR=$( cd "$( dirname "${BASH_SOURCE[0]}")/.." && pwd )
# Start SGX Rust Docker container.
# (DCMMC) 进入一个有 SGX SDL 和 SGX SSL 的环境，方便编译
docker stop tc-devel
docker rm tc-devel
docker run --rm -td \
  --name "tc-devel" \
  -v ${ROOTDIR}:/code \
  -e "SGX_SDK=/opt/intel/sgxsdk" \
  --net=host \
  -w /build \
  bl4ck5un/tc-sgx-sdk:latest \
  /usr/bin/env bash

sleep 2s

docker exec -it tc-devel \
  bash -c 'source /opt/intel/sgxsdk/environment && /code/privatenet/fix_deps_enter_sgx.sh'

# 9 instances of tc server
for i in $(seq 1 9); do
  echo 'Run tc_server '$i
  docker exec -it tc-devel \
    bash -c 'cp -v /tmp/tc_config /tmp/tc_config_'$i' && sed -i "5s/8123/8'$i'23/g" /tmp/tc_config_'$i
  docker exec -td tc-devel \
    bash -c 'source /opt/intel/sgxsdk/environment && /tc/bin/tc -c /tmp/tc_config_'$i' > /code/privatenet/logs/tc_server_'$i'.log 2>&1'
  printf 'Done\n\n'
done

echo 'TC server log stored in privatenet/logs/tc_server.log'
sleep 2s
cat logs/tc_server_2.log

IFS=$'\n'
for i in `ps aux | egrep relay`; do
  kill `echo $i | awk '{print $2}'` 2>/dev/null
done
rm -vf tc.log.bin
python3 ../python-relay/relay.py --voting --sgx_wallet ${add_sgx} --tc_contract ${add_tc} > logs/relay.log 2>&1 &
sleep 3s
cat relay.log

echo 'Deploy and run load_balancer and voting in SCONE.'
. start_scone.sh

printf '\n\nAll done. address info stored in privatenet/address_info.txt.\n'
deploy="Deploy(add_tc='"${add_tc}"', add_app='"${add_app}"')"
read -p "Do you want to start a test request? (Y/N)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    python3 -c 'from test_tc import *; d = '${deploy}'; d.demo();'
  echo
fi
echo "You can now use "${deploy}" to test."
exit 0
