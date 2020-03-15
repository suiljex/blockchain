import json
import flask
import requests
from urllib.parse import urlparse 
from uuid import uuid4

from blockchain import Blockchain
from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator

class BlockchainClient():
  def __init__(self):
    self._blockchain = Blockchain()
    self._nodes = set()
    self._crypto = BlockchainCrypto()
    self._validator = BlockchainValidator()
    self._private_key = str()
    self._public_key = str()
    self._address = str()
    self._balance = 0
    self._availible_transactions = dict()
    self._auth_ready = False
    self._bc_ready = False
    # self._identifier = str(uuid4()).replace('-', '')
    
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
      response = requests.get(f'http://{node}/chain')

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

  def calculate_balance(self):
    if not self._blockchain or not self._auth_ready:
      return 0

    used_transactions = list()
    self._availible_transactions = dict()
    self._balance = 0

    for block in self._blockchain.export_chain():
      for tx in block['data']['transactions']:
        if tx['header']['sender'] == self._address:
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

    if self._balance < amount:
      return False

    tx_balance = 0
    tx_inputs = list()

    for tx_id in self._availible_transactions:
      for tx_output in self._availible_transactions[tx_id]['data']['outputs']:
        if tx_output['recipient'] == self._address:
          tx_balance += tx_output['amount']
      tx_inputs.append({'tx_id', tx_id})
      if tx_balance >= amount:
        break

    tx_data = {
      'inputs' : tx_inputs,
      'outputs' : [
        {
          'recipient' : recipient,
          'amount' : amount
        },
        {
          'recipient' : self._address,
          'amount' : tx_balance - amount
        }
      ]
    }

    tx_data_hash = self._crypto.hash(tx_data)
    signature = self._crypto.sign(tx_data_hash, self._private_key)

    tx_header = {
      'type' : 1,
      'sender' : self._address,
      'public_key' : self._public_key,
      'signature' : signature
    }

    transaction = {
      tx_header,
      tx_data
    }

    for node in self._nodes:
      response = requests.post(f'http://{node}/transactions/new')

    return True


app = flask.Flask(__name__)
client = BlockchainClient()

@app.route('/transaction/new', methods=['POST'])
def new_transaction():
  values = request.get_json()
  if node.new_transaction(values['transaction']) == True:
    return 201
  else:
    return "Wrong transaction", 400

@app.route('/init', methods=['POST'])
def init_client():
  client.generate_auth()
  return "Client initialised", 200

@app.route('/chain', methods=['GET'])
def full_chain():
  response = {
    'chain' : node.blockchain
  }
  return flask.jsonify(response), 200

@app.route('/balance', methods=['GET'])
def calculate_balance():
  response = {
    'balance' : client.calculate_balance()
  }
  return flask.jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
  values = request.get_json()

  nodes = values.get('nodes')
  if nodes is None:
    return "Error: Please supply a valid list of nodes", 400

  for other_node in nodes:
    client.register_node(other_node)

  response = {
    'message': 'New nodes have been added'
  }
  return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
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

  return jsonify(response), 200

if __name__ == '__main__':
  from argparse import ArgumentParser

  parser = ArgumentParser()
  parser.add_argument('-p', '--port', default=6000, type=int, help='port to listen on')
  args = parser.parse_args()
  port = args.port

  app.run(host='0.0.0.0', port=port)