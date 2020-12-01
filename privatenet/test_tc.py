import json
import pprint
import web3
from web3 import Web3, HTTPProvider
from solc import compile_standard
from math import ceil


def string_to_bytes32_array(text):
    arr = [text[i*32: (i+1):32].ljust(32, '0') for i in range(ceil(len(text) / 32))]
    return [bytes(a, 'utf-8') for a in arr]


def submit_request(req_type=0, req_data='{"test": "SELECT AVG(Price) FROM Products;"}'):
    gas_estimate = ins_app.functions.request(
        req_type,
        string_to_bytes32_array(req_data)).estimateGas()
    print(f"Sending transaction with gas_estimate={gas_estimate}\n")
    tx_hash = ins_app.functions.request(
        req_type,
        string_to_bytes32_array(req_data)
    ).transact({
        'from': w3.eth.accounts[0],
        'value': 25000000000, 'gas': 500000})
    receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print("Transaction receipt mined:")
    pprint.pprint(dict(receipt))
    print("\nTransaction status:")
    pprint.pprint(receipt["status"])


def get_tc_req_events():
    filter = w3.eth.filter(
        {'fromBlock': 0, 'toBlock': 'latest', 'address': w3.toChecksumAddress(add_tc),
         'topics': ['0x295780ea261767c398d062898e5648587d7b8ca371ffd203be8b4f9a43454ffa']})
    events = filter.get_new_entries()
    logs = [ins_tc.events.RequestInfo().processReceipt(
        w3.eth.getTransactionReceipt(
            e['transactionHash'])) for e in events]

    return events


def get_app_req_events():
    filter = w3.eth.filter(
        {'fromBlock': 0, 'toBlock': 'latest', 'address': w3.toChecksumAddress(add_app),
         'topics': [w3.keccak(
             text="Request(int64,address,uint,bytes32[])").hex()]})
    events = filter.get_new_entries()
    logs = [ins_app.events.Request().processReceipt(
        w3.eth.getTransactionReceipt(
            e['transactionHash'])) for e in events]
    return events


if __name__ == '__main__':
    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            "Application.sol": {'content': '\n'.join(open('contracts/Application.sol').readlines())},
            "TownCrier.sol": {'content': '\n'.join(open('contracts/TownCrier.sol').readlines())},
        },
        "settings": {
            "outputSelection": {"*": {"*": ["metadata", "evm.bytecode", "evm.bytecode.sourceMap"]}}
        }
    })
    w3 = Web3(HTTPProvider('http://localhost:8000'))
    w3.eth.defaultAccount = w3.eth.accounts[0]
    bytecode_app = compiled_sol['contracts']['Application.sol']['Application']['evm']['bytecode']['object']
    bytecode_tc = compiled_sol['contracts']['TownCrier.sol']['TownCrier']['evm']['bytecode']['object']
    abi_app = json.loads(compiled_sol['contracts']['Application.sol']['Application']['metadata'])['output']['abi']
    abi_tc = json.loads(compiled_sol['contracts']['TownCrier.sol']['TownCrier']['metadata'])['output']['abi']
    app = w3.eth.contract(abi=abi_app, bytecode=bytecode_app)
    tc = w3.eth.contract(abi=abi_tc, bytecode=bytecode_tc)
    tx_hash_tc = tc.constructor().transact()
    tx_receipt_tc = w3.eth.waitForTransactionReceipt(tx_hash_tc)
    add_tc = tx_receipt_tc.contractAddress
    ins_tc = w3.eth.contract(address=add_tc, abi=abi_tc)
    tx_hash_app = app.constructor(add_tc).transact()
    tx_receipt_app = w3.eth.waitForTransactionReceipt(tx_hash_app)
    add_app = tx_receipt_app.contractAddress
    ins_app = w3.eth.contract(address=add_app, abi=abi_app)
    pprint.pprint(f'Deploy contracts: \nTownCrier: {add_tc},' +
          f'\nApplication: {add_app}')
