echo 'Removing old accounts'
sudo pkill geth
sudo rm -rf node0{1,2,3}
echo 'Generate and initialize new accounts'
mkdir node0{1,2,3}
geth --datadir node01 account new
geth --datadir node02 account new
geth --datadir node03 account new

