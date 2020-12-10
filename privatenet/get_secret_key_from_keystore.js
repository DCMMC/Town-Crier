// (DCMMC) 从 ethereum 的 keystore json 中导出私钥，注意保护密码！
// Ref: https://medium.com/codechain/managing-ethereum-private-keys-4838ac9fa935

// Test only work on 0.6.5
const jswallet = require('ethereumjs-wallet')
const readline = require("readline");
const fs = require('fs');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// const json = {
//     version: 3,
//     id: 'f834ca09-6a3f-4bff-b2a3-fe471393e194',
//     address: '75a426f8136891afe4244347ce6931f5826e5cc7',
//     crypto: {
//         ciphertext: '1c0c43ec8c71756f83b97cdf141e269737fe26e936cde5ddb074abb0dc5c244d',
//         cipherparams: {iv: 'e77638e7b6baf35667aea62d4721a937'},
//         cipher: 'aes-128-ctr',
//         kdf: 'scrypt',
//         kdfparams:
//             {
//                 dklen: 32,
//                 salt: '2b994a37e5295f0ae2ac6f2ddfdd7e2919bcbe3e779a8b329aff5d312407ec14',
//                 n: 262144,
//                 r: 8,
//                 p: 1
//             },
//         mac: '389c1b287d955b92c7306740f7381805bf3424aedbe16705e43097db96712ce4'
//     }
// };
// const wallet = jswallet.fromV3(json, "password");
// console.log();

rl.question('Which node?\n', (node) => {
  rl.question('password of the node?\n', (pwd) => {
    let keystore = JSON.parse(fs.readFileSync(node + '/keystore/' +
      fs.readdirSync(node + '/keystore')[0]));
    let wallet = jswallet.fromV3(keystore, pwd);
    console.log("Private key " + wallet.getPrivateKey().toString("hex"))
    process.stderr.write(wallet.getPrivateKey().toString("hex"))
    process.exit(0);
  })
})
