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
        self._bcfile = BlockchainFile()
        self._filename_chain = "node_blockchain.bin"
        self._filename_privk = "node_private_key.bin"
        self._private_key = str()
        self._public_key = str()
        self._address = str()
        self._auth_ready = False
        self._bc_ready = False

    def save(self):
        if not self._blockchain or not self._auth_ready:
            return False

        self._bcfile.filename = self._filename_chain
        if self._bcfile.save(self._blockchain.export_chain()) is False:
            self._bcfile.filename = ""
            return False
        self._bcfile.filename = self._filename_privk
        if self._bcfile.save(self._private_key) is False:
            self._bcfile.filename = ""
            return False
        self._bcfile.filename = ""
        return True

    def load(self):
        self._bcfile.filename = self._filename_privk
        temp_privk = self._bcfile.load()

        self._bcfile.filename = self._filename_chain
        temp_chain = self._bcfile.load()

        self._bcfile.filename = ""

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

    @property
    def blockchain(self):
        return self._blockchain.export_chain()

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
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self._validator.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self._blockchain.import_chain(new_chain)
            return True

        return False

    def new_transaction(self, transaction):
        if not self._blockchain or not self._auth_ready:
            return None

        if self._validator.valid_transaction(transaction, self._blockchain.export_chain()) is True:
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

        block_data = {
            'transactions': [tx_reward] + self._pending_transactions
        }

        self._pending_transactions = list()

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

        if self._blockchain.new_block(block) is False:
            return None
        return block

    def _proof_of_work(self, data, difficulty):
        # last_block_hash = hash(self._blockchain.last_block['header'])
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
    if node.save() is False:
        return "Error", 400
    return "Data saved", 200


@app.route('/data/load', methods=['POST'])
def load_data():
    if node.load() is False:
        return "Error", 400
    return "Data loaded", 200


@app.route('/auth/generate', methods=['POST'])
def gen_auth():
    node.generate_auth()
    return "Auth generated", 200


@app.route('/auth/load', methods=['POST'])
def load_auth():
    values = flask.request.get_json()
    if values is None:
        return "Error", 400

    if values['private_key'] is None:
        return "Error", 400

    if node.load_auth(values['private_key']) is False:
        return "Error", 400

    return "Auth loaded", 200


@app.route('/mine', methods=['POST'])
def mine():
    block = node.mine_block()
    if block is None:
        return "Node error", 400

    response = {
        'block': block
    }
    return flask.jsonify(response), 200


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    values = flask.request.get_json()
    if values is None:
        return "Error", 400

    if values['transaction'] is None:
        return False

    tx_json = values['transaction']
    transaction = json.loads(tx_json)

    if node.new_transaction(transaction) is None:
        return "Wrong transaction", 400
    else:
        return "Success", 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': node.blockchain,
        'length': len(node.blockchain)
    }
    return flask.jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = flask.request.get_json()
    if values is None:
        return "Error: Please supply a valid list of nodes", 400

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for other_node in nodes:
        node.register_node(other_node)

    response = {
        'message': 'New nodes have been added'
    }
    return flask.jsonify(response), 201


@app.route('/nodes/resolve', methods=['POST'])
def consensus():
    replaced = node.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced'
        }
    else:
        response = {
            'message': 'Our chain is authoritative'
        }

    return flask.jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
