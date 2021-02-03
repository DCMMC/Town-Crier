from flask import Flask
from flask import request
from mysql.connector import connect, Error
import logging
from web3 import Web3

import grpc
import tc_pb2
import tc_pb2_grpc

logging.basicConfig(format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)-4d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)
# 9 tc server instances
stubs = [tc_pb2_grpc.towncrierStub(
    grpc.insecure_channel(f'127.0.0.1:8{i}23')) for i in range(1, 10)]
# RR scheduler
rr_curr = 0
connection = connect(
    host="127.0.0.1",
    user='root',
    password='97294597',
)


def load_balance_scheduler():
    global rr_curr
    rr_curr += 1
    rr_curr %= 9
    return [stubs[i % 9] for i in range(rr_curr, rr_curr + 3)]


def execute_sql(sql):
    logger.info(f'execute sql: {sql}')
    # [ref] https://realpython.com/python-mysql/
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql)
            res = ''
            for data in cursor:
                res += str(data) + '\n'
            logger.info(f'sql res: {res}')
            return res if len(res) else 'status: OK'
    except Error as e:
        logger.error('Error when execute sql: ' + str(e))
        return 'status: error, ' + str(e)


@app.route('/request', methods=['POST'])
def request_tc():
    # get sql query result
    # select 3 tc according to load balancer (RR)
    # assign rawTransaction generation task to 3 tc
    req = request.json
    logger.info(f'(DCMMC) load balancer get request: {req}')
    if req['type'] == 0:
        sql_raw = req['data']
        sql = req['data'].rstrip('0')
        res = execute_sql(sql)
        res_bytes = res.encode()
        if len(res_bytes) % 32 != 0:
            res_bytes = res_bytes + bytes([0] * (32 - len(res_bytes) % 32))
        req = {
            'id': req['id'],
            # this type indicates tc server only need to
            # generate raw transaction
            'type': 2,
            # concat an array of bytes
            'data': bytes(Web3.keccak(bytes([req['type']]) + sql_raw.encode())) + res_bytes,
            'nonce': req['nonce']
        }
        res = ''
        for stub in load_balance_scheduler():
            logger.info(f'stub {stub}, req: {req}')
            res += str(stub.process(tc_pb2.Request(**req))) + '\n'
            logger.info(f'stub {stub} return: {res}')
        return res
    else:
        # (TODO) return code (e.g. 403)
        return f'error type {req["type"]}'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000,
            ssl_context=('flask_cert/cert.pem', 'flask_cert/key.pem'))
