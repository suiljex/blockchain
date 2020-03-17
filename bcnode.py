import json
import flask
import time
import requests
import re
from urllib.parse import urlparse
from blockchain import Blockchain

from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator
from bcfile import BlockchainFile


class BlockchainNode():
    def __init__(self):
        self._nodes = set()
        self._pending_transactions = list()
        self._blockchain = Blockchain()
        self._validator = BlockchainValidator()
        self._crypto = BlockchainCrypto()
        self._bcfile_chain = BlockchainFile()
        self._bcfile_privk = BlockchainFile()
        self._bcfile_chain.filename = "node_blockchain.bin"
        self._bcfile_privk.filename = "node_private_key.bin"
        self._private_key = str()
        self._public_key = str()
        self._address = str()
        self._auth_ready = False
        self._bc_ready = False

    def save(self):
        if not self._blockchain or not self._auth_ready:
            return False

        if self._bcfile_chain.save(self._blockchain.export_chain()) is False:
            return False
        if self._bcfile_privk.save(self._private_key) is False:
            return False
        return True

    def load(self):
        temp_privk = self._bcfile_privk.load()
        temp_chain = self._bcfile_chain.load()

        if temp_privk is None or temp_chain is None:
            return False

        if self.load_auth(temp_privk) is False:
            return False

        if self._blockchain.import_chain(temp_chain) is False:
            return False

        return True

    def generate_auth(self):
        self._private_key = self._crypto.generate_private_key()
        self._public_key = self._crypto.generate_public_key(self._private_key)
        self._address = self._crypto.generate_address(self._public_key)
        self._auth_ready = True

    def load_auth(self, private_key):
        regex = re.compile('[a-f0-9]{64}')
        match = regex.match(private_key)
        if bool(match) is False:
            return False
        self._private_key = private_key
        self._public_key = self._crypto.generate_public_key(self._private_key)
        self._address = self._crypto.generate_address(self._public_key)
        self._auth_ready = True
        return True

    def export_auth(self):
        return {
            'private_key': self._private_key,
            'public_key': self._public_key,
            'address': self._address
        }

    @property
    def blockchain(self):
        return self._blockchain.export_chain()

    def get_block_by_index(self, index):
        return self._blockchain.get_block_by_index(index)

    def get_block_by_id(self, id):
        return self._blockchain.get_block_by_id(id)

    def get_transaction_by_id(self, id):
        return self._blockchain.get_transaction_by_id(id)

    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self._nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self._nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def resolve_conflicts(self):
        neighbours = self._nodes
        new_chain = None

        max_length = len(self._blockchain.export_chain())

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
            except requests.ConnectionError:
                break

            if response.status_code == 200:
                length = response.json()['data']['length']
                chain = response.json()['data']['chain']

                if length > max_length and self._validator.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            temp_pending_txs = list()
            for block in self._blockchain.export_chain():
                for tx in block['data']['transactions']:
                    temp_pending_txs.append(tx)
            self._blockchain.import_chain(new_chain)
            self._pending_transactions += temp_pending_txs
            self._pending_transactions = self._select_transactions(0)
            return True
        return False

    def new_transaction(self, transaction):
        if not self._blockchain or not self._auth_ready:
            return None

        if self._validator.valid_transaction_t(transaction, self._blockchain.export_blockchain_data()) is True:
            self._pending_transactions.append(transaction)
            return transaction
        return None

    def mine_block(self):
        if not self._blockchain or not self._auth_ready:
            return None

        temp_difficulty = self._crypto.calculate_difficulty(len(self._blockchain.export_chain()))
        temp_amount = self._crypto.calculate_reward(temp_difficulty)

        tx_data = {
            'outputs': [
                {
                    'recipient': self._address,
                    'amount': temp_amount
                }
            ]
        }

        tx_data_hash = self._crypto.hash(tx_data)
        signature = self._crypto.sign(tx_data_hash, self._private_key)

        tx_header = {
            'type': 1,
            'sender': self._address,
            'public_key': self._public_key,
            'signature': signature
        }

        tx_reward = {
            'header': tx_header,
            'data': tx_data
        }

        selected_txs = self._select_transactions(42)
        block_data = {
            'transactions': [tx_reward] + selected_txs
        }

        block_header = {
            'version': 1,
            'timestamp': time.time(),
            'previous_block': self._crypto.hash(self._blockchain.last_block['header']),
            'nonce': 0,
            'difficulty': temp_difficulty,
            'data_hash': self._crypto.hash(block_data)
        }

        block_header['nonce'] = self._proof_of_work(block_header['data_hash'], temp_difficulty)

        block = {
            'header': block_header,
            'data': block_data
        }

        if self._blockchain.add_block(block) is False:
            self._pending_transactions = self._select_transactions(0)
            return None

        self._pending_transactions = [elem for elem in self._pending_transactions if elem not in selected_txs]
        self._pending_transactions = self._select_transactions(0)
        return block

    def _select_transactions(self, amount=0):
        selected_txs = list()
        blockchain_data = self._blockchain.export_blockchain_data()
        local_used_transactions = blockchain_data['used_txs']
        local_transactions_map_id = blockchain_data['tx_map_id']
        # local_blocks_map_id = blockchain_data['blk_map_id']

        flag_all = False
        if amount == 0:
            flag_all = True

        selected = 0
        for tx in self._pending_transactions:
            if selected >= amount and flag_all == False:
                break
            if self._validator.valid_transaction_t(tx, blockchain_data) is True:
                if tx['header']['type'] == 2:
                    for tx_input in tx['data']['inputs']:
                        local_used_transactions[tx_input['tx_id']] = tx['header']['sender']
                local_transactions_map_id[self._crypto.hash(tx['header'])] = tx
                selected_txs.append(tx)
                selected += 1

        return selected_txs

    def _proof_of_work(self, data, difficulty):
        nonce = 0
        while self._crypto.valid_proof(data, nonce, difficulty) is False:
            nonce += 1
        return nonce

    @property
    def last_block(self):
        return self._blockchain.last_block

    @property
    def nodes(self):
        return self._nodes


app = flask.Flask(__name__)
node = BlockchainNode()


@app.route('/data/save', methods=['POST'])
def save_data():
    response = dict()
    if node.save() is False:
        response['status'] = "ERROR"
        response['message'] = "Error occured while saving data to file"
        return flask.jsonify(response), 500
    response['status'] = "SUCCESS"
    response['message'] = "Data successfuly has been saved to file"
    return flask.jsonify(response), 200


@app.route('/data/load', methods=['POST'])
def load_data():
    response = dict()
    if node.load() is False:
        response['status'] = "ERROR"
        response['message'] = "Error occured while loading data from file"
        return flask.jsonify(response), 500
    response['status'] = "SUCCESS"
    response['message'] = "Data successfuly has been loaded from file"
    return flask.jsonify(response), 200


@app.route('/auth/generate', methods=['POST'])
def gen_auth():
    node.generate_auth()
    response = dict()
    response['status'] = "SUCCESS"
    response['message'] = "Authentication data has been generated"
    return flask.jsonify(response), 200


@app.route('/auth/import', methods=['POST'])
def load_auth():
    response = dict()
    values = flask.request.get_json()
    if values is None or values['private_key'] is None:
        response['status'] = "ERROR"
        response['message'] = "No data was recieved"
        return flask.jsonify(response), 400

    if node.load_auth(values['private_key']) is False:
        response['status'] = "ERROR"
        response['message'] = "No private key was detected"
        return flask.jsonify(response), 400

    response['status'] = "SUCCESS"
    response['message'] = "Authentication data has been imported"
    return flask.jsonify(response), 202


@app.route('/auth/export', methods=['GET'])
def export_auth():
    response = dict()
    response['status'] = "SUCCESS"
    response['message'] = "Auth data"
    response['data'] = node.export_auth()
    return flask.jsonify(response), 200


@app.route('/block/mine', methods=['POST'])
def mine():
    response = dict()
    block = node.mine_block()
    if block is None:
        response['status'] = "ERROR"
        response['message'] = "Error occured while mining block"
        return flask.jsonify(response), 500
    response['status'] = "SUCCESS"
    response['message'] = "Block has been successfuly mined and saved to blockchain"
    response['data'] = {
        'block': block
    }
    return flask.jsonify(response), 200


@app.route('/block/get/index', methods=['GET'])
def get_block_index():
    response = dict()
    values = flask.request.get_json()
    if values is None or values['index'] is None:
        response['status'] = "ERROR"
        response['message'] = "No data was recieved"
        return flask.jsonify(response), 400

    blk_index = int(values['index'])
    block = node.get_block_by_index(blk_index)
    if block is None:
        response['status'] = "ERROR"
        response['message'] = "Block is not found"
        return flask.jsonify(response), 500

    response['status'] = "SUCCESS"
    response['message'] = "Block"
    response['data'] = {
        'block': block
    }
    return flask.jsonify(response), 200


@app.route('/block/get/id', methods=['GET'])
def get_block_id():
    response = dict()
    values = flask.request.get_json()
    if values is None or values['id'] is None:
        response['status'] = "ERROR"
        response['message'] = "No data was recieved"
        return flask.jsonify(response), 400

    blk_id = str(values['id'])
    block = node.get_block_by_id(blk_id)
    if block is None:
        response['status'] = "ERROR"
        response['message'] = "Block is not found"
        return flask.jsonify(response), 500

    response['status'] = "SUCCESS"
    response['message'] = "Block"
    response['data'] = {
        'block': block
    }
    return flask.jsonify(response), 200


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    response = dict()
    values = flask.request.get_json()
    if values is None or values['transaction'] is None:
        response['status'] = "ERROR"
        response['message'] = "No data was recieved"
        return flask.jsonify(response), 400

    tx_json = values['transaction']
    transaction = json.loads(tx_json)

    if node.new_transaction(transaction) is None:
        response['status'] = "ERROR"
        response['message'] = "Transaction was rejected"
        return flask.jsonify(response), 400

    response['status'] = "SUCCESS"
    response['message'] = "Transaction will be added to the next block"
    return flask.jsonify(response), 201


@app.route('/transaction/get/id', methods=['GET'])
def get_transaction_id():
    response = dict()
    values = flask.request.get_json()
    if values is None or values['id'] is None:
        response['status'] = "ERROR"
        response['message'] = "No data was recieved"
        return flask.jsonify(response), 400

    blk_id = str(values['id'])
    transaction = node.get_transaction_by_id(blk_id)
    if transaction is None:
        response['status'] = "ERROR"
        response['message'] = "Transaction is not found"
        return flask.jsonify(response), 500

    response['status'] = "SUCCESS"
    response['message'] = "Transaction"
    response['data'] = {
        'transaction': transaction
    }
    return flask.jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = dict()
    response['status'] = "SUCCESS"
    response['message'] = "Chain"
    response['data'] = {
        'chain': node.blockchain,
        'length': len(node.blockchain)
    }
    return flask.jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    response = dict()
    values = flask.request.get_json()
    if values is None or values['nodes'] is None:
        response['status'] = "ERROR"
        response['message'] = "Please supply a valid list of nodes"
        return flask.jsonify(response), 400

    nodes = values['nodes']
    for other_node in nodes:
        node.register_node(other_node)

    response['status'] = "SUCCESS"
    response['message'] = "New nodes have been added"
    return flask.jsonify(response), 201


@app.route('/nodes/resolve', methods=['POST'])
def consensus():
    response = dict()
    replaced = node.resolve_conflicts()
    response['status'] = "SUCCESS"
    if replaced:
        response['message'] = "Our chain have been replaced"
    else:
        response['message'] = "Our chain is authoritative"

    return flask.jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
