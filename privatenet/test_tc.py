import json
import pprint
import web3
from web3 import Web3, HTTPProvider
from solc import compile_standard
from math import ceil
import time
import logging
from web3.logs import DISCARD

logging.basicConfig(format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)-4d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)


class Deploy():
    def __init__(self, add_tc=None, add_app=None):
        self.w3 = Web3(HTTPProvider('http://localhost:8000'))
        compiled_sol = compile_standard({
            "language": "Solidity",
            "sources": {
                "Application.sol": {'content': '\n'.join(
                    open('contracts/Application.sol').readlines())},
                "TownCrier.sol": {'content': '\n'.join(
                    open('contracts/TownCrier.sol').readlines())},
            },
            "settings": {
                "outputSelection": {"*": {"*": [
                    "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]}}
            }
        })
        self.w3.eth.defaultAccount = self.w3.eth.accounts[0]
        self.bytecode_app = compiled_sol['contracts']['Application.sol']['Application'][
            'evm']['bytecode']['object']
        self.bytecode_tc = compiled_sol['contracts']['TownCrier.sol']['TownCrier'][
            'evm']['bytecode']['object']
        self.abi_app = json.loads(compiled_sol['contracts']['Application.sol'][
            'Application']['metadata'])['output']['abi']
        self.abi_tc = json.loads(compiled_sol['contracts']['TownCrier.sol'][
            'TownCrier']['metadata'])['output']['abi']
        self.add_tc = add_tc
        self.add_app = add_app
        self.ins_tc, self.ins_app = self.import_instance(add_tc, add_app)
        self.processed_log = set()

    @staticmethod
    def string_to_bytes32_array(text):
        arr = [text[i*32: (i+1)*32].ljust(32, '0') for i in range(ceil(len(text) / 32))]
        return [bytes(a, 'utf-8') for a in arr]

    def submit_request(self, gas=20 * 10 ** 4, req_type=0,
                       req_data='show databases;'):
        gas_estimate = self.ins_app.functions.request(
            req_type,
            self.string_to_bytes32_array(req_data)).estimateGas()
        logger.debug(f"Sending transaction with gas_estimate={gas_estimate}\n")
        gas_price = 5 * 10 ** 10
        tx_hash = self.ins_app.functions.request(
            req_type,
            self.string_to_bytes32_array(req_data)
        ).transact({
            'from': self.w3.eth.accounts[0],
            'value': gas * gas_price , 'gas': gas, 'gasPrice': gas_price})
        receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        logger.info("Transaction receipt mined:")
        # pprint.pprint(dict(receipt))
        logs0 = self.ins_app.events.Request().processLog(receipt['logs'][-1])
        if len(receipt['logs']) == 0:
            logger.warning('Internal error encountered, logs are empty!')
        elif len(receipt['logs']) == 1:
            logger.warning('Encouter error when call request in Application:')
            pprint.pprint(logs0)
        else:
            logger.info('Success request.')
            logs1 = self.ins_tc.events.RequestInfo().processLog(receipt['logs'][-2])
            logger.debug(f'RequestInfo in TownCrier: {logs1}')

    def get_tc_req_events(self):
        filter_evt = self.w3.eth.filter(
            {'fromBlock': 0, 'toBlock': 'latest',
             'address': self.w3.toChecksumAddress(self.add_tc),
             'topics': ['0x295780ea261767c398d062898e5648587d7b8ca371ffd203be8b4f9a43454ffa']})
        events = filter_evt.get_all_entries()
        logs = [self.ins_tc.events.RequestInfo().processReceipt(
            self.w3.eth.getTransactionReceipt(
                e['transactionHash']), errors=DISCARD) for e in events]
        return events

    def get_app_req_events(self):
        filter_evt = self.w3.eth.filter(
            {'fromBlock': 0, 'toBlock': 'latest',
             'address': self.w3.toChecksumAddress(self.add_app),
             'topics': [self.w3.keccak(
                 text="Request(int64,address,uint,bytes32[])").hex()]})
        events = filter_evt.get_all_entries()
        logs = [self.ins_app.events.Request().processReceipt(
            self.w3.eth.getTransactionReceipt(
                e['transactionHash']), errors=DISCARD) for e in events]
        return events

    @staticmethod
    def parse_response(event):
        reqId = event['args']['requestId']
        error = event['args']['error']
        data = event['args']['data']
        return reqId, error, data

    def wait_response(self):
        # 目前只能串行不能并行
        max_wait = 100
        for i in range(max_wait):
            time.sleep(1)
            lines = list(open('logs/relay.log').readlines())
            for idx in range(len(lines)):
                if 'response sent and mined' in lines[-idx] and lines[-idx] not in self.processed_log:
                    self.processed_log.add(lines[-idx])
                    logger.info('find response, wait for 2s.')
                    time.sleep(2)
                    result_tx = lines[-idx].strip().split()[-1]
                    receipt = self.w3.eth.getTransactionReceipt(result_tx)
                    # print(receipt)
                    debug_info = self.ins_tc.events.Debug().processReceipt(
                        receipt, errors=DISCARD)
                    logger.debug(f'debug_info: {debug_info}')
                    deliver = self.ins_tc.events.DeliverInfo().processReceipt(
                        receipt, errors=DISCARD)
                    logger.debug(f'DeliverInfo event in TownCrier:\n{deliver}')
                    response = self.ins_app.events.Response().processReceipt(
                        receipt, errors=DISCARD)
                    logger.debug(f'Final Response event in Application:\n{response}')
                    reqId, error, data = self.parse_response(response[0])
                    logger.info(f'\n{"#"*60}\nerror: {error}\ndata:\n{data.rstrip(bytes([0]))}\n{"#"*60}')
                    return
            logger.debug('wait for 1s.')
        logger.warning('Error: timeout')

    def demo(self):
        sql_list = [
            "CREATE DATABASE IF NOT EXISTS test_db;",
            "USE test_db;",
            "DROP TABLE IF EXISTS tb_courses;",
            "CREATE TABLE tb_courses (course_id INT NOT NULL AUTO_INCREMENT, "
            "course_name CHAR(40) NOT NULL, course_grade FLOAT NOT NULL, "
            "course_info CHAR(100) NULL, PRIMARY KEY(course_id));",
            "SELECT * FROM tb_courses;",
            "INSERT INTO tb_courses (course_id,course_name,course_grade,course_info) "
            "VALUES(1,'Network',3,'Course info');",
            "SELECT * FROM tb_courses;",
        ]
        for idx, sql in enumerate(sql_list):
            logger.info(f'Test SQL {idx}: {sql}')
            self.submit_request(req_type=0, req_data=sql)
            self.wait_response()


    def import_instance(self, tc, app):
        ins_tc = self.w3.eth.contract(address=tc, abi=self.abi_tc)
        ins_app = self.w3.eth.contract(address=app, abi=self.abi_app)
        return ins_tc, ins_app

    def deploy(self):
        app = self.w3.eth.contract(abi=self.abi_app, bytecode=self.bytecode_app)
        tc = self.w3.eth.contract(abi=self.abi_tc, bytecode=self.bytecode_tc)
        tx_hash_tc = tc.constructor().transact()
        tx_receipt_tc = self.w3.eth.waitForTransactionReceipt(tx_hash_tc)
        add_tc = tx_receipt_tc.contractAddress
        ins_tc = self.w3.eth.contract(address=add_tc, abi=self.abi_tc)
        tx_hash_app = app.constructor(add_tc).transact()
        tx_receipt_app = self.w3.eth.waitForTransactionReceipt(tx_hash_app)
        add_app = tx_receipt_app.contractAddress
        ins_app = self.w3.eth.contract(address=add_app, abi=self.abi_app)
        return add_app, add_tc


if __name__ == '__main__':
    app, tc = Deploy().deploy()
    print(f'TownCrier: {tc} ' +
          f'Application: {app}')
