import json
from bccrypto import BlockchainCrypto

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

if __name__ == '__main__':
  print("This module is a dependecy")
  exit(0)