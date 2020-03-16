import json
import flask
import requests
import re
from urllib.parse import urlparse

from blockchain import Blockchain
from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator
from bcfile import BlockchainFile


class BlockchainClient():
    def __init__(self):
        self._blockchain = Blockchain()
        self._nodes = set()
        self._crypto = BlockchainCrypto()
        self._validator = BlockchainValidator()
        self._bcfile = BlockchainFile()
        self._filename_chain = "client_blockchain.bin"
        self._filename_privk = "client_private_key.bin"
        self._private_key = str()
        self._public_key = str()
        self._address = str()
        self._balance = 0
        self._availible_transactions = dict()
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

    def calculate_balance(self):
        if not self._blockchain or not self._auth_ready:
            return 0

        used_transactions = list()
        self._availible_transactions = dict()
        self._balance = 0

        for block in self._blockchain.export_chain():
            for tx in block['data']['transactions']:
                if tx['header']['sender'] == self._address and tx['header']['type'] == 2:
                    for tx_output in tx['data']['outputs']:
                        self._balance -= tx_output['amount']
                    for tx_input in tx['data']['inputs']:
                        used_transactions.append(tx_input['tx_id'])

                for tx_output in tx['data']['outputs']:
                    if tx_output['recipient'] == self._address:
                        self._balance += tx_output['amount']
                        self._availible_transactions[self._crypto.hash(tx['header'])] = tx

        for tx_id in used_transactions:
            self._availible_transactions.pop(tx_id, None)
        return self._balance

    def make_transaction(self, recipient, amount):
        if not self._blockchain or not self._auth_ready:
            return False

        self.calculate_balance()

        if self._balance < amount or amount <= 0:
            return False

        tx_balance = 0
        tx_inputs = list()

        for tx_id in self._availible_transactions:
            for tx_output in self._availible_transactions[tx_id]['data']['outputs']:
                if tx_output['recipient'] == self._address:
                    tx_balance += tx_output['amount']
            tx_inputs.append({'tx_id': tx_id})
            if tx_balance >= amount:
                break

        tx_data = {
            'inputs': tx_inputs,
            'outputs': [
                {
                    'recipient': recipient,
                    'amount': amount
                },
                {
                    'recipient': self._address,
                    'amount': tx_balance - amount
                }
            ]
        }

        tx_data_hash = self._crypto.hash(tx_data)
        signature = self._crypto.sign(tx_data_hash, self._private_key)

        tx_header = {
            'type': 2,
            'sender': self._address,
            'public_key': self._public_key,
            'signature': signature
        }

        transaction = {
            'header': tx_header,
            'data': tx_data
        }

        for node in self._nodes:
            try:
                response = requests.post(f'http://{node}/transaction/new', json={"transaction" : json.dumps(transaction)})
            except requests.ConnectionError:
                break

            if response.status_code == 201:
                return True

        return False


app = flask.Flask(__name__)
client = BlockchainClient()


@app.route('/data/save', methods=['POST'])
def save_data():
    if client.save() is False:
        return "Error", 400
    return "Data saved", 200


@app.route('/data/load', methods=['POST'])
def load_data():
    if client.load() is False:
        return "Error", 400
    return "Data loaded", 200


@app.route('/auth/generate', methods=['POST'])
def gen_auth():
    client.generate_auth()
    return "Auth generated", 200


@app.route('/auth/load', methods=['POST'])
def load_auth():
    values = flask.request.get_json()
    if values is None:
        return "Error", 400

    if values['private_key'] is None:
        return "Error", 400

    if client.load_auth(values['private_key']) is False:
        return "Error", 400

    return "Auth loaded", 200


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    values = flask.request.get_json()
    if values is None:
        return "Error", 400

    if values['amount'] is None or values['recipient'] is None:
        return "Error", 400

    amount = values['amount']
    recipient = values['recipient']

    if client.make_transaction(recipient, amount) is False:
        return "Error", 400

    return "Success", 201


@app.route('/balance', methods=['GET'])
def calculate_balance():
    response = {
        'balance': client.calculate_balance()
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
        client.register_node(other_node)

    response = {
        'message': 'New nodes have been added'
    }
    return flask.jsonify(response), 201


@app.route('/nodes/resolve', methods=['POST'])
def consensus():
    replaced = client.resolve_conflicts()

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
    parser.add_argument('-p', '--port', default=6000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
