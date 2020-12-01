#!/bin/env python

import time
import pickle
import os
import logging
import requests
import json
import argparse
import sys

from web3 import Web3, HTTPProvider

logging.basicConfig(format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)-4d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)


class TcLog:
    def __init__(self):
        self.last_processed_block = 0
        self.processed_txn_in_next_block = []
        self.n_txn_in_next_block = 0

    def __str__(self):
        return "last_processed_block={0}".format(self.last_processed_block)


class Request:
    def __init__(self, txid, data):
        self.txid = txid
        self.data = data


class BaseConfig:
    SGX_WALLET_ADDR = ""
    TC_CONTRACT_ADDR = ""
    TC_CONTRACT_BLOCK_NUM = 0


class ConfigSim(BaseConfig):
    # (DCMMC) 需要在这里配置好两个区块链地址
    SGX_WALLET_ADDR = Web3.toChecksumAddress("0xc82ad85e461b85b17dc02f0173127798636b3ede")
    TC_CONTRACT_ADDR = Web3.toChecksumAddress("0x7FF5Fa610d96ecd74EAc58C4d5f05e16b574492E")
    # (DCMMC) TC 合约开始的区块号, relay 将会从这里开始遍历所有区块来找到 TC request
    TC_CONTRACT_BLOCK_NUM = 0


class ConfigHwAzure(BaseConfig):
    SGX_WALLET_ADDR = Web3.toChecksumAddress("0x3A8DE03F19C7C4C139B171978F87BFAC9FFE99C0")
    # https://rinkeby.etherscan.io/address/0x9ec1874ff1def6e178126f7069487c2e9e93d0f9
    TC_CONTRACT_ADDR = Web3.toChecksumAddress("0x9eC1874FF1deF6E178126f7069487c2e9e93D0f9")
    TC_CONTRACT_BLOCK_NUM = 2118268


class TCMonitor:
    ETH_RPC_ADDRESS = 'http://localhost:8000'

    TC_CORE_RPC_URL = "http://localhost:8123"
    # (DCMMC) TC 合约发出的 RequestInfo 信号的 Keccak-256 hash
    # RequestInfo(uint64,uint8,address,uint256,address,bytes32,uint256,bytes32[])
    # 这个可以直接用 truffle develop 交互式界面输入 tc 的 instance 名称，然后找到这个 event,
    # 下面就有它的 hash
    # TC_REQUEST_TOPIC = "0x295780EA261767C398D062898E5648587D7B8CA371FFD203BE8B4F9A43454FFA"
    TC_REQUEST_TOPIC = "0x295780ea261767c398d062898e5648587d7b8ca371ffd203be8b4f9a43454ffa"

    SIM_NET = 'sim'
    TEST_NET = 'rinkeby'

    NUM_OF_RETRY_ON_NETWORK_ERROR = 10

    def __init__(self, network, pickle_file):
        if network == self.SIM_NET:
            self.config = ConfigSim()
        elif network == self.TEST_NET:
            self.config = ConfigHwAzure()
        else:
            raise KeyError("{0} is unknown".format(network))

        self.PICKLE_FILE = pickle_file

        logger.info('pickle_file: {0}'.format(self.PICKLE_FILE))
        logger.info('sgx wallet addr: {0}'.format(self.config.SGX_WALLET_ADDR))
        logger.info('tc contract addr: {0}'.format(self.config.TC_CONTRACT_ADDR))

        if os.path.exists(self.PICKLE_FILE):
            try:
                with open(self.PICKLE_FILE, 'rb') as f:
                    self.record = pickle.load(f)
            except Exception as e:
                logger.error("cannot load log {0}".format(e))
                self.record = TcLog()
        else:
            logging.debug("creating empty log")
            self.record = TcLog()

        # start processing with the block in which tc contract is mined
        self.record.last_processed_block = max(self.record.last_processed_block,
                                               self.config.TC_CONTRACT_BLOCK_NUM)

        self.w3 = Web3(HTTPProvider(self.ETH_RPC_ADDRESS))
        time.sleep(2)
        if not self.w3.isConnected():
            logger.info('cannot connect to {0}'.format(self.ETH_RPC_ADDRESS))
            sys.exit(1)
        else:
            logger.info('connected to {0}'.format(self.w3.clientVersion))

    def _get_requests_in_block(self, block):
        # (DCMMC) topics 就是 TC contract 发出的 RequestInfo 事件的签名
        filter_obj = {'fromBlock': block, 'toBlock': block,
                      'address': self.config.TC_CONTRACT_ADDR,
                      'topics': [self.TC_REQUEST_TOPIC]}
        logs = self.w3.eth.getLogs(filter_obj)
        logger.info("{0} requests find in block {1}".format(len(logs), block))
        requests = []
        for log in logs:
            requests.append(Request(Web3.toHex(log['transactionHash']), log['data']))
        return requests

    def _update_record_one_request(self, req):
        self.record.processed_txn_in_next_block.append(req)
        with open(self.PICKLE_FILE, 'wb') as f:
            pickle.dump(self.record, f)
        logger.info('done update')

    def _update_record_one_block(self):
        self.record.last_processed_block += 1
        self.record.processed_txn_in_next_block = []
        with open(self.PICKLE_FILE, 'wb') as f:
            pickle.dump(self.record, f)
        # logger.info('done processing block {0}'.format(self.record.last_processed_block))

    def _process_request(self, req):
        logger.info("processing request {0}".format(req.txid))

        nonce = self.w3.eth.getTransactionCount(self.config.SGX_WALLET_ADDR)

        params = dict(
            data=req.data,
            txid=req.txid,
            nonce=nonce,
        )

        payload = {
            'method': 'process',
            'params': params,
            'jsonrpc': '2.0',
            'id': 0,
        }

        resp = requests.post(self.TC_CORE_RPC_URL, data=json.dumps(payload),
                             headers={'content-type': 'application/json'}).json()
        if 'error' in resp:
            logger.error('Error: {0}'.format(resp['error']))
        else:
            error_code = resp['result']['error_code']
            response_tx = resp['result']['response']
            if error_code != 0:
                logger.error('Error in tx: {0}'.format(error_code))
            logger.info('response from enclave: {0}'.format(response_tx))
            # (DCMMC) 发送回复到区块链
            # ref: https://web3py.readthedocs.io/en/stable/web3.eth.html#web3.eth.Eth.sendRawTransaction
            txid = self.w3.eth.sendRawTransaction(response_tx)
            self._update_record_one_request(req)
            logger.info("response sent {0}".format(Web3.toHex(txid)))

    def loop(self):
        next_block = self.config.TC_CONTRACT_BLOCK_NUM
        while True:
            try:
                # (DCMMC) 暴力遍历
                next_block = max(next_block, self.record.last_processed_block + 1)
                geth_block = self.w3.eth.blockNumber

                if next_block > geth_block:
                    logger.debug("waiting for block #{0} (geth is at #{1})".format(next_block, geth_block))
                    time.sleep(2)
                    continue
                reqs = self._get_requests_in_block(next_block)
                if len(reqs):
                    logger.info("find reqs in block {0}".format(next_block))
                for req in reqs:
                    if req not in self.record.processed_txn_in_next_block:
                        retry = 0
                        while retry < self.NUM_OF_RETRY_ON_NETWORK_ERROR:
                            time.sleep(2 ** retry)
                            try:
                                self._process_request(req)
                                break
                            except requests.RequestException as e:
                                logger.error('exception: {0}'.format(str(e)))
                            except Exception as e:
                                logger.error('exception: {0}'.format(str(e)))
                            retry += 1

                self._update_record_one_block()
            # catch everything (e.g. errors in RPC call with geth) and continue
            except Exception as e:
                logger.error('exception: {0}'.format(str(e)))
                time.sleep(2)


parser = argparse.ArgumentParser(description="Town Crier Ethereum relay")
parser.add_argument('-v', action='store_true', dest='verbose', help='Verbose')
parser.add_argument('-t', action='store_true', dest='testnet', help='Enable testnet')
parser.add_argument('--db', action='store', dest='database', default='/relay/tc.bin',
                    help='where to store the runtime log')

args = parser.parse_args()
args.parser = parser

logger.setLevel('INFO')
# (DCMMC) 默认不采用 testnet，采用 privatenet
network = TCMonitor.SIM_NET

if args.verbose:
    logger.setLevel('DEBUG')

if args.testnet:
    network = TCMonitor.TEST_NET

monitor = TCMonitor(network, args.database)
monitor.loop()
