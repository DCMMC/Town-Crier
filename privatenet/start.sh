# You must manually edit the alloc addresses to the
# generated address (public key) in genesis.json!
geth --datadir node01 init genesis.json
geth --datadir node02 init genesis.json
geth --datadir node03 init genesis.json
echo 'Start running node01, node02, node03'
nohup geth --identity node01 --rpc --rpcport "8000" --rpccorsdomain '*' --datadir node01 --port "30303" --nodiscover --rpcapi "eth,net,web3,personal,miner,admin,debug" --networkid 1900 --nat "any" --allow-insecure-unlock --ethstats node01:s3cr3t@localhost:3000 >node01.log 2>&1 &
nohup geth --identity node02 --rpc --rpcport "8001" --rpccorsdomain '*' --datadir node02 --port "30313" --nodiscover --rpcapi "eth,net,web3,personal,miner,admin,debug" --networkid 1900 --nat "any" --allow-insecure-unlock --ethstats node02:s3cr3t@localhost:3000 >node02.log 2>&1 &
nohup geth --identity node03 --rpc --rpcport "8002" --rpccorsdomain '*' --datadir node03 --port "30323" --nodiscover --rpcapi "eth,net,web3,personal,miner,admin,debug" --vmdebug --networkid 1900 --nat "any" --allow-insecure-unlock --ethstats node03:s3cr3t@localhost:3000 >node03.log 2>&1 &
echo 'unlock accounts.'
sleep 2s
geth attach http://localhost:8000 --exec 'personal.unlockAccount(eth.accounts[0], "97294597", 36000)'
geth attach http://localhost:8001 --exec 'personal.unlockAccount(eth.accounts[0], "97294597", 36000)'
geth attach http://localhost:8002 --exec 'personal.unlockAccount(eth.accounts[0], "97294597", 36000)'
echo 'add peers.'
adminNode=`geth attach http://localhost:8000 --exec 'admin.nodeInfo.enode'`
geth attach http://localhost:8001 --exec "admin.addPeer("${adminNode}")"
geth attach http://localhost:8002 --exec "admin.addPeer("${adminNode}")"
echo 'start miner'
geth attach http://localhost:8000 --exec "miner.start(4)"

echo 'Done.'
