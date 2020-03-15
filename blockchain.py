import json
import flask
import secrets
import ecdsa
import codecs
import hashlib
import time
import requests
from urllib.parse import urlparse 
from uuid import uuid4

class BlockchainCrypto():
  @staticmethod
  def valid_proof(last_hash, nonce, difficulty):
    guess = f'{last_hash}{nonce}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    guess_hash_binary = str(bin(int(guess_hash, base=16)))[2:]
    return guess_hash_binary[difficulty:] == "0" * difficulty

  @staticmethod
  def hash(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

  @staticmethod
  def generate_private_key():
    bits = secrets.randbits(256)
    bits_hex = hex(bits)
    private_key = bits_hex[2:]
    return private_key

  @staticmethod
  def generate_public_key(private_key):
    private_key_bytes = bytes.fromhex(private_key)
    public_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    public_key_bytes = public_key.to_string()
    public_key_hex = public_key_bytes.hex()
    return public_key_hex

  @staticmethod
  def generate_address(public_key):
    public_key_bytes = bytes.fromhex(public_key)
    address_hash = hashlib.sha256(public_key_bytes)
    address = address_hash.hexdigest()
    return address

  @staticmethod
  def sign(message, private_key):
    private_key_bytes = bytes.fromhex(private_key)
    message_bytes = bytes(message, "ascii")
    private_key_ready = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    signature_bytes = private_key_ready.sign(message_bytes)
    signature = signature_bytes.hex()
    return signature

  @staticmethod
  def verify(message, signature, public_key):
    public_key_bytes = bytes.fromhex(public_key)
    message_bytes = bytes(message, "ascii")
    public_key_ready = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
    try:
      result = public_key_ready.verify(bytes.fromhex(signature), message_bytes)
    except ecdsa.keys.BadSignatureError:
      result = False
    return result

  @staticmethod
  def calculate_difficulty(hight):
    return 0

  @staticmethod
  def calculate_reward(difficulty):
    return 1


class BlockchainValidator():
  def __init__(self):
    self._crypto = BlockchainCrypto()

  
  def valid_chain(self, chain):
    service_data = {
      'hight': 0,
      'txs_list': dict(),
      'used_transactions': set(),
      'previous_block' : None,
      'difficulty' : 0
    }

    return self._valid_chain(chain, service_data)
    
  def valid_block(self, block, chain):
    service_data = {
      'hight': 0,
      'txs_list': dict(),
      'used_transactions': set(),
      'previous_block' : None,
      'difficulty' : 0
    }

    if self._valid_chain(chain, service_data) == False:
      return False

    return self._valid_block(block, service_data)
        
  def valid_transaction(self, transaction, chain):
    service_data = {
      'hight': 0,
      'txs_list': dict(),
      'used_transactions': set(),
      'previous_block' : None,
      'difficulty' : 0
    }

    if self._valid_chain(chain, service_data) == False:
      return False
    
    return self._valid_transaction(chain, service_data) == False
    
  def _valid_chain(self, chain, service_data):
    if len(chain) <= 1:
      return True

    service_data['previous_block'] = chain[0]
    for block in chain[1:]:
      if self._valid_block(block, service_data) == False:
        return False
      service_data['previous_block'] = block
      service_data['hight'] += 1

    return True

  def _valid_block(self, block, service_data):
    
    temp_txs_list = dict()
    service_data['difficulty'] = self._crypto.calculate_difficulty(service_data['hight'])

    if block['header']['difficulty'] != service_data['difficulty']:
      return False
    
    if block['header']['data_hash'] != self._crypto.hash(block['data']):
      return False

    if self._crypto.valid_proof(hash(service_data['previous_block']['header']), block['header']['nonce'], block['header']['difficulty']) == False:
      return False

    for transaction in block['data']['transactions']:
      if self._valid_transaction(transaction, service_data) == False:
        return False
      temp_txs_list[hash(transaction['header'])] = transaction

    service_data['txs_list'].update(temp_txs_list)
    return True

  def _valid_transaction(self, transaction, service_data):
    inputs_sum = 0
    outputs_sum = 0

    if transaction['header']['sender'] != self._crypto.generate_address(transaction['header']['public_key']):
        return False

    if self._crypto.verify(json.dumps(transaction['data'], sort_keys=True).encode() 
              , transaction['header']['signature']
              , transaction['header']['public_key']) == False:
      return False
    
    if transaction['header']['type'] == 1:
      for output_tx in transaction['data']['outputs']:
        if output_tx['amount'] < 0:
          return False
        outputs_sum += output_tx['amount']

      if outputs_sum != self._crypto.calculate_reward(service_data['difficulty']):
        return False

    elif transaction['header']['type'] == 2:
      for input_tx in transaction['data']['inputs']:
        for tx_out in service_data['txs_list'][input_tx['tx_id']]['data']['outputs']:
          if tx_out['recipient'] == input_tx['recipient']:
            inputs_sum += tx_out['amount']

        full_tx = f"{input_tx['tx_id']}:{input_tx['recipient']}"
        if full_tx in service_data['used_transactions']:
          return False
        service_data['used_transactions'].append(full_tx)

      for output_tx in transaction['data']['outputs']:
        if output_tx['amount'] < 0:
          return False
        outputs_sum += output_tx['amount']

      if inputs_sum != outputs_sum:
        return False
    return True

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

  def generate_auth(self):
    self._private_key = self._crypto.generate_private_key()
    self._public_key = self._crypto.generate_public_key(self._private_key)
    self._address = self._crypto.generate_address(self._public_key)

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


  # def new_transaction(self, sender, public_key, signature, inputs, outputs):
  def new_transaction(self, transaction):
    if self._validator.valid_transaction(transaction, self._blockchain) == True:
      self._pending_transactions.append(transaction)
      return transaction
    return None

  def mine_block(self):
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
    # self._identifier = str(uuid4()).replace('-', '')
    
  def register_node(self, address):
    parsed_url = urlparse(address)
    if parsed_url.netloc:
      self._nodes.add(parsed_url.netloc)
    elif parsed_url.path:
      self._nodes.add(parsed_url.path)
    else:
      raise ValueError('Invalid URL')

  def generate_auth(self):
    self._private_key = self._crypto.generate_private_key()
    self._public_key = self._crypto.generate_public_key(self._private_key)
    self._address = self._crypto.generate_address(self._public_key)

  def calculate_balance(self):
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

bcc = BlockchainCrypto()
g_private_key = bcc.generate_private_key()
g_public_key = bcc.generate_public_key(g_private_key)
g_address = bcc.generate_address(g_public_key)
g_signature = bcc.sign("kek", g_private_key)
g_result = bcc.verify("kek", g_signature, g_public_key)
print(g_signature)
print(g_result)


print(g_private_key)
print(g_public_key)
print(g_address)
print(type(g_private_key))
print(type(g_public_key))
print(type(g_address))

class Blockchain:
  def __init__(self):
    self._chain = list()
    self._crypto = BlockchainCrypto()
    self._validator = BlockchainValidator()
    # self._hight = 0
    # self._used_transactions = set()
    # self._txs_list = dict()
    self._genesis_block()

  # @property
  def export_chain(self):
    return self._chain

  def import_chain(self, chain):
    # hight = 0
    # used_transactions = set()
    # txs_list = dict()
    # previous_block = None

    # hight = 0
    # used_transactions = set()
    # txs_list = dict()
    # previous_block = None

    # if len(chain) <= 1:
    #   return True

    # previous_block = chain[0]
    # for block in chain[1:]:
    #   if self._validator.valid_block(block, previous_block, hight, txs_list, used_transactions) == False:
    #     return False
    #   previous_block = block
    #   hight += 1

    if self._validator.valid_chain(chain) == True:
      self._chain = chain
      return True

    return False
    # self._hight = hight
    # self._used_transactions = used_transactions
    # self._txs_list = txs_list

    # for transction in self._pending_transactions:
    #   if self._valid_transaction(transction, self._txs_list, self._used_transactions) == False:
    #     del transction

    # return True
        
  def _genesis_block(self):
    self._chain = list()

    data = {
      'transactions' : list()
    }

    header = {
      'version' : 1,
      'timestamp' : time.time(),
      'previous_block' : "0" * 32,
      'nonce' : 0,
      'difficulty' : 0,
      'data_hash' : self._crypto.hash(data)
    }

    block = {
      'header' : header,
      'data' : data
    }

    self._chain.append(block)
    return block
    
  def new_block(self, block):
    if self._validator.valid_block(block, self._chain) == True:
      # self.pending_transactions = []
      self._chain.append(block)
      return True
    return False

  # def resolve_conflicts(self):
  #   pass

  @property
  def last_block(self):
    return self._chain[-1]

  @property
  def difficulty(self):
    return 32

app = flask.Flask(__name__)
node = BlockchainNode()

@app.route('/mine', methods=['GET'])
def mine():
  pass

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
  pass

@app.route('/chain', methods=['GET'])
def full_chain():
  pass

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
  pass

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
  pass


if __name__ == '__main__':
  from argparse import ArgumentParser

  parser = ArgumentParser()
  parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
  args = parser.parse_args()
  port = args.port

  app.run(host='0.0.0.0', port=port)