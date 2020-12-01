### TC 配置过程

#### SGX WALLET

使用 node get_secret_key_from_keystore.js 获得 SGX WALLET 账户的私钥, 修改 src/Enclave/eth_ecdsa.cpp 中的 PREDEFINED_SECKEY 为上述私钥，然后执行

/tc/bin/tc-keygen --enclave /tc/enclave/enclave.debug.so --keygen /tmp/key.txt

来获得 sealed.sig_key 放到 tc 的 config 文件（config-privatenet-sim）里面去

修改 relay.py 中的 SGX WALLET 地址和 TC 智能合约地址

#### TC 智能合约地址

修改 config 文件（config-privatenet-sim）和 relay.py 文件

### Truffle

修改 truffle-config.js 中的地址



truffle develop 进入开发者模式

migrate --reset 编译运行智能合约

var ins_app = await Application.deployed()

var ins_tc = await TownCrier.deployed()

TC 合约的地址：

TownCrier.address

查看事件的签名：

ins_app.contract.events

ins_tc.contract.events

App 发起请求（从 trffule 的账户发起的转帐，gas 金额为 25000000000，也就是 TC_FEE）：

var r = await ins_app.request(0, [web3.utils.asciiToHex('test')], {from: accounts[0], value: 25000000000, gas: 500000})

获得请求结果中的 Event：

r.logs[0].args

获得区块链上当前智能合约发出的所有 Request 事件：

var events = await ins_app.getPastEvents('Request', {fromBlock: 0, toBlock: 'latest'})

按照 topics 来过滤事件日志

var reqs = await web3.eth.getPastLogs({fromBlock: 0, toBlock: 'latest', topics: ['0x295780ea261767c398d062898e5648587d7b8ca371ffd203be8b4f9
a43454ffa']})

### 常用网站

hash：https://emn178.github.io/online-tools/keccak_256.html

货币转换：https://coinmarketcap.com/converter/eth/usd/

Ethereum 单位转换：https://eth-converter.com/

Remix IDE：http://remix.ethereum.org/