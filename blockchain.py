import time

from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator


class Blockchain:
    def __init__(self):
        self._blockchain = list()
        self._crypto = BlockchainCrypto()
        self._validator = BlockchainValidator()
        self._genesis_block()

    def export_chain(self):
        return self._blockchain

    def import_chain(self, chain):
        if self._validator.valid_chain(chain) is True:
            self._chain = chain
            return True

        return False

    def _genesis_block(self):
        self._blockchain = list()

        data = {
            'transactions': list()
        }

        header = {
            'version': 1,
            'timestamp': time.time(),
            'previous_block': "0" * 32,
            'nonce': 0,
            'difficulty': 0,
            'data_hash': self._crypto.hash(data)
        }

        block = {
            'header': header,
            'data': data
        }

        self._blockchain.append(block)
        return block

    def new_block(self, block):
        if self._validator.valid_block(block, self._chain) is True:
            # self.pending_transactions = []
            self._blockchain.append(block)
            return True
        return False

    @property
    def last_block(self):
        return self._blockchain[-1]


if __name__ == '__main__':
    print("This module is a dependecy")
    exit(0)
