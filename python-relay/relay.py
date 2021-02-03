#!/bin/env python
import time
import os
import json
import logging
import requests
import argparse
import sys
import grpc
from web3 import Web3, HTTPProvider
from solc import compile_standard
import traceback

import random

import tc_pb2
import tc_pb2_grpc

logging.basicConfig(format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)-4d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)


class TCMonitor:
    ETH_RPC_ADDRESS = 'http://localhost:8000'
    TC_CORE_RPC_URL = "localhost:8123"
    # (DCMMC) TC 合约发出的 RequestInfo 信号的 Keccak-256 hash
    # RequestInfo(uint64,uint8,address,uint256,address,bytes32,uint256,bytes32[])
    # 这个可以直接用 truffle develop 交互式界面输入 tc 的 instance 名称，然后找到这个 event,
    # 下面就有它的 hash
    TC_REQUEST_TOPIC = "0x295780ea261767c398d062898e5648587d7b8ca371ffd203be8b4f9a43454ffa"
    SIM_NET = 'sim'
    NUM_OF_RETRY_ON_NETWORK_ERROR = 10
    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            "TownCrier.sol": {'content': '\n'.join(
                open('../privatenet/contracts/TownCrier.sol').readlines())},
        },
        "settings": {
            "outputSelection": {"*": {"*": [
                "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]}}
        }
    })

    def __init__(self, config):
        assert config.TC_CONTRACT_BLOCK_NUM >= 0
        self.config = config
        print(self.config)
        self.w3 = Web3(HTTPProvider(self.ETH_RPC_ADDRESS))
        self.abi_tc = json.loads(self.compiled_sol['contracts']['TownCrier.sol'][
            'TownCrier']['metadata'])['output']['abi']
        self.config.SGX_WALLET_ADDR = Web3.toChecksumAddress(self.config.SGX_WALLET_ADDR)
        self.config.TC_CONTRACT_ADDR = Web3.toChecksumAddress(self.config.TC_CONTRACT_ADDR)
        self.tc_contract = self.w3.eth.contract(
            address=self.config.TC_CONTRACT_ADDR, abi=self.abi_tc)

        logger.info('sgx wallet addr: {0}'.format(self.config.SGX_WALLET_ADDR))
        logger.info('tc contract addr: {0}'.format(self.config.TC_CONTRACT_ADDR))
        # create a grpc client
        channel = grpc.insecure_channel(self.TC_CORE_RPC_URL)
        self.stub = tc_pb2_grpc.towncrierStub(channel)
        self.w3 = Web3(HTTPProvider(self.ETH_RPC_ADDRESS))
        time.sleep(2)
        if not self.w3.isConnected():
            logger.info('cannot connect to {0}'.format(self.ETH_RPC_ADDRESS))
            sys.exit(1)
        else:
            logger.info('connected to {0}'.format(self.w3.clientVersion))

    def _process_request(self, req):
        nonce = self.w3.eth.getTransactionCount(self.config.SGX_WALLET_ADDR)
        req = req['args']
        if args.voting:
            req = {
                'id': req['id'],
                'type': req['requestType'],
                # concat an array of bytes
                'data': ''.join([r.decode('utf-8') for r in req['requestData']]),
                'nonce': nonce
            }
            # address of load balancer
            response = requests.post(url='https://127.0.0.1:9000/request',
                                     json=req,
                                     verify=False)
            print(f'Load balancer return: {response}')
        else:
            grpc_req = tc_pb2.Request(
                id=req['id'],
                type=req['requestType'],
                # concat an array of bytes
                data=b''.join(req['requestData']),
                nonce=nonce)
            response = self.stub.process(grpc_req)
            if response.error_code != 0:
                logger.error("Enclave returned error %d", response.error_code)
            logger.info(f'response_tx: {response.response_tx}')
            logger.info('response from enclave: %s', response.response_tx.hex())
            response_tx = response.response_tx
            # (DCMMC) 发送回复到区块链
            # ref: https://web3py.readthedocs.io/en/stable/web3.eth.html#web3.eth.Eth.sendRawTransaction
            txid = self.w3.eth.sendRawTransaction(response_tx)
            receipt = self.w3.eth.waitForTransactionReceipt(txid)
            logger.info("response sent and mined: {0}".format(Web3.toHex(txid)))

    def loop(self):
        filter_all_requests = self.tc_contract.events.RequestInfo.createFilter(
            fromBlock=self.config.TC_CONTRACT_BLOCK_NUM,)
        logger.info("filter for RequestInfo created, fromBlock=%s, ID %s.",
                         self.config.TC_CONTRACT_BLOCK_NUM,
                         filter_all_requests.filter_id)
        while True:
            try:
                # (DCMMC) 暴力遍历
                for entry in filter_all_requests.get_new_entries():
                    print(f'process entry {entry["args"]["id"]}')
                    self._process_request(entry)
            except grpc.RpcError as rpc_error:
                logger.error('RPC failure: %s', rpc_error)
            except ValueError as e:
                try:
                    if e.args[0]['message'] == 'filter not found':
                        # if e is caused by that the filter we're using has been retired, we create a new one.
                        logger.warning("filter %s not found. Probably retired.",
                                            filter_all_requests.filter_id)
                        filter_all_requests = self.tc_contract.events.RequestInfo.createFilter(
                            fromBlock='latest')
                        logger.info("filter for RequestInfo created, fromBlock=latest, ID %s.",
                                         filter_all_requests.filter_id)
                except Exception:
                    # if the except e is not due to "filter not found", pass it through (i.e., re-raise)
                    logger.error('exception: %s', e)
                    raise e
            except Exception as e:
                logger.error('exception: %s', e)
                traceback.print_exc()
            time.sleep(2)


parser = argparse.ArgumentParser(description="Town Crier Ethereum relay")
parser.add_argument('-v', action='store_true', dest='verbose', help='Verbose')
parser.add_argument('--sgx_wallet', action='store', dest='SGX_WALLET_ADDR', type=str,
                    help='sgx wallet address in the blockchain')
parser.add_argument('--tc_contract', action='store', dest='TC_CONTRACT_ADDR',
                    help='TC contract address in the blockchain')
parser.add_argument('--start_block', action='store', dest='TC_CONTRACT_BLOCK_NUM', type=int,
                    default=0, help='block number where TC contract start running, default=0')
parser.add_argument('--voting', action='store_true', dest='voting')

args = parser.parse_args()
args.parser = parser

logger.setLevel('INFO')
# (DCMMC) 默认不采用 testnet，采用 privatenet

if args.verbose:
    logger.setLevel('DEBUG')

monitor = TCMonitor(args)
monitor.loop()
