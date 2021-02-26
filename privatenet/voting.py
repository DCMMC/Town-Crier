from flask import Flask
from flask import request
import logging
from web3 import Web3, HTTPProvider
import os
import base64

logging.basicConfig(format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)-4d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)
w3 = Web3(HTTPProvider('http://127.0.0.1:8000'))
app = Flask(__name__)
voting_list = {}


@app.route('/send_raw_tx', methods=['GET'])
def send_raw_tx():
    # 2-out-of-3 majority voting
    # according to request id
    logger.info('req=' + str(request.args))
    req_id = request.args['id']
    tc_id = request.args['tc']
    tx = bytes(base64.b64decode(request.args['tx'].replace(' ', '+').encode('ascii')))
    logger.info(f'received tx with id={req_id}: {tx.hex()}')
    if req_id not in voting_list:
        voting_list[req_id] = {tc_id: tx}
        return 'rawTx received, need voting'
    elif tc_id in voting_list[req_id]:
        logger.info('do not repeat send tx of same req_id!')
        return 'do not repeat send tx of same req_id!'
    elif len(voting_list[req_id]) == 1:
        voting_list[req_id][tc_id] = tx
        return 'rawTx received, need voting'
    elif len(voting_list[req_id]) == 2:
        voting_list[req_id][tc_id] = tx
        # voting
        resp_32 = [v for v in voting_list[req_id].values()]
        if resp_32[0][137:137+32] == resp_32[1][137:137+32] or \
                resp_32[0][137:137+32] == resp_32[2][137:137+32]:
            resp_32 = resp_32[0]
        elif resp_32[1][137:137+32] == resp_32[2][137:137+32]:
            resp_32 = resp_32[1]
        else:
            # 三个结果都不一样！
            logger.error('all the 3 results are different from each other!')
            # (TODO) 有更好的错误反馈机制！而不是现在这样
            return 'voting failed!'
        txid = w3.eth.sendRawTransaction(resp_32)
        receipt = w3.eth.waitForTransactionReceipt(txid)
        log_str = "response sent and mined: {0}".format(Web3.toHex(txid))
        logger.info(log_str)
        with open(os.path.dirname(os.path.abspath(__file__)) + '/logs/relay.log', 'a') as f:
            f.write(log_str + '\n')
        return 'rawTx received, voting done'
    else:
        return f'error, unexpected number of tc ({len(voting_list[req_id])})'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001,
            ssl_context=('/app/flask_cert/cert.pem', '/app/flask_cert/key.pem'))
