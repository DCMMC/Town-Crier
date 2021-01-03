// (DCMMC) 从 ethereum 的 keystore json 中导出私钥，注意保护密码！
// Ref: https://medium.com/codechain/managing-ethereum-private-keys-4838ac9fa935

// Test only work on 0.6.5
const jswallet = require('ethereumjs-wallet')
const readline = require("readline");
const fs = require('fs');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr
});

rl.question('Which node?\n', (node) => {
  rl.question('password of the node?\n', (pwd) => {
    let keystore = JSON.parse(fs.readFileSync(node + '/keystore/' +
      fs.readdirSync(node + '/keystore')[0]));
    let wallet = jswallet.fromV3(keystore, pwd);
    process.stderr.write("Private key " + wallet.getPrivateKey().toString("hex"))
    process.stdout.write(wallet.getPrivateKey().toString("hex"))
    process.exit(0);
  })
})
