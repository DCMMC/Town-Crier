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

echo 'Modify config according to new account addresses.'
sed -i '15s/\("0x\)[0-9a-fA-F]\{40\}/"0x'${addr01}'/' genesis.json
sed -i '15s/\("0x\)[0-9a-fA-F]\{40\}/"0x'${addr02}'/' genesis.json
sed -i '15s/\("0x\)[0-9a-fA-F]\{40\}/"0x'${addr03}'/' genesis.json

