from flask import Flask
from flask import request
import logging

logging.basicConfig(format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)-4d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)
voting_list = {}


@app.route('/send_raw_tx', methods=['GET'])
def send_raw_tx():
    # 2-out-of-3 majority voting
    # according to request id
    req_id = request.form['id']
    tc_id = request.form['tc']
    tx = request.form['tx']
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
        elif:
            # 三个结果都不一样！
            logger.error('all the 3 results are different from each other!')
            # (TODO) 有更好的错误反馈机制！而不是现在这样
            return 'voting failed!'
        return 'rawTx received, voting done'
    else:
        return f'error, unexpected number of tc ({len(voting_list[req_id])})'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
