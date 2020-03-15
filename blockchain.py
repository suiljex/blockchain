import time
from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator

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

if __name__ == '__main__':
  print("This module is a dependecy")
  exit(0)