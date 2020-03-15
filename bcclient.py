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

if __name__ == '__main__':
  from argparse import ArgumentParser

  parser = ArgumentParser()
  parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
  args = parser.parse_args()
  port = args.port

#   app.run(host='0.0.0.0', port=port)