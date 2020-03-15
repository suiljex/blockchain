import json
import flask
import time
import requests
import pickle
from urllib.parse import urlparse 
from uuid import uuid4

from blockchain import Blockchain
from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator

class BlockchainNode():
  def __init__(self):
    self._nodes = set()
    self._pending_transactions = list()
    self._blockchain = Blockchain()
    self._validator = BlockchainValidator()
    self._crypto = BlockchainCrypto()
    # self._identifier = str(uuid4()).replace('-', '')
    self._private_key = str()
    self._public_key = str()
    self._address = str()
    self._auth_ready = False
    self._bc_ready = False

  def generate_auth(self):
    self._private_key = self._crypto.generate_private_key()
    self._public_key = self._crypto.generate_public_key(self._private_key)
    self._address = self._crypto.generate_address(self._public_key)
    self._auth_ready = True

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

  def new_transaction(self, transaction):
    if not self._blockchain or not self._auth_ready:
      return None

    if self._validator.valid_transaction(transaction, self._blockchain) == True:
      self._pending_transactions.append(transaction)
      return transaction
    return None

  def mine_block(self):
    if not self._blockchain or not self._auth_ready:
      return None

    tx_data = {
      'outputs' : [
        {
          'recipient' : self._address,
          'amount' : 0 # TODO difficulty
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

    tx_reward = {
      tx_header,
      tx_data
    }

    block_data = {
      'transactions' : [tx_reward] + self._pending_transactions
    }

    block_header = {
      'version' : 1,
      'timestamp' : time.time(),
      'previous_block' : self._crypto.hash(self._blockchain.last_block['header']),
      'nonce' : 0,
      'difficulty' : 0, # TODO difficulty
      'data_hash' : self._crypto.hash(block_data)
    }

    block_header['nonce'] = self._proof_of_work(block_header['data_hash'])

    block = {
      'header' : block_header,
      'data' : block_data
    }

    return self._blockchain.new_block(block)

  def _proof_of_work(self, data):
    # last_block_hash = hash(self._blockchain.last_block['header'])
    nonce = 0
    while self._crypto.valid_proof(data, nonce, self._blockchain.difficulty) == False:
      nonce += 1
    return nonce

  @property
  def last_block():
    return self._blockchain.last_block

  @property
  def nodes():
    return self._nodes


app = flask.Flask(__name__)
node = BlockchainNode()

@app.route('/mine', methods=['GET'])
def mine():
  node.mine_block()
  response = {
    'block' : node.last_block
  }
  return flask.jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
  values = request.get_json()
  if node.new_transaction(values['transaction']) == True:
    return 201
  else:
    return "Wrong transaction", 400

@app.route('/chain', methods=['GET'])
def full_chain():
  response = {
    'chain' : node.blockchain
  }
  return flask.jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
  values = request.get_json()

  nodes = values.get('nodes')
  if nodes is None:
    return "Error: Please supply a valid list of nodes", 400

  for other_node in nodes:
    node.register_node(other_node)

  response = {
    'message': 'New nodes have been added'
  }
  return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
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

  return jsonify(response), 200

if __name__ == '__main__':
  from argparse import ArgumentParser

  parser = ArgumentParser()
  parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
  args = parser.parse_args()
  port = args.port

  app.run(host='0.0.0.0', port=port)