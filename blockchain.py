import time

from bccrypto import BlockchainCrypto
from bcvalidator import BlockchainValidator


class Blockchain:
    def __init__(self):
        self._chain = list()
        self._blocks_map_id = dict()
        self._transactions_map_id = dict()
        self._used_transactions = dict()
        self._crypto = BlockchainCrypto()
        self._validator = BlockchainValidator()
        self._genesis_block()

    def export_chain(self):
        return list(self._chain)

    def get_block_by_index(self, index):
        if index >= 0 and index < len(self._chain):
            return dict(self._chain[index])
        return None

    def get_block_by_id(self, id):
        return self._blocks_map_id.get(id, None)

    def get_transaction_by_id(self, id):
        return self._transactions_map_id.get(id, None)

    def export_blockchain_data(self):
        return {
            'chain': list(self._chain),
            'tx_map_id': dict(self._transactions_map_id),
            'blk_map_id': dict(self._blocks_map_id),
            'used_txs': dict(self._used_transactions)
        }

    def import_chain(self, chain):
        if self._validator.valid_chain(chain) is True:
            self._chain = chain
            self._rebuild_blockcahin_data()
            return True

        return False

    def _rebuild_blockcahin_data(self):
        self._blocks_map_id = dict()
        self._transactions_map_id = dict()
        self._used_transactions = dict()
        for block in self._chain:
            for tx in block['data']['transactions']:
                if tx['header']['type'] == 2:
                    for tx_input in tx['data']['inputs']:
                        self._used_transactions[tx_input['tx_id']] = tx['header']['sender']
                self._transactions_map_id[self._crypto.hash(tx['header'])] = tx
            self._blocks_map_id[self._crypto.hash(block['header'])] = block

    def _genesis_block(self):
        self._chain = list()

        data = {
            'transactions': list()
        }

        header = {
            'version': 1,
            'timestamp': time.time(),
            'previous_block': "0" * 64,
            'nonce': 0,
            'difficulty': 0,
            'data_hash': self._crypto.hash(data)
        }

        block = {
            'header': header,
            'data': data
        }

        self._chain.append(block)
        self._blocks_map_id[self._crypto.hash(block['header'])] = block
        return block

    def add_block(self, block):
        if self._validator.valid_block_t(block, self.export_blockchain_data()) is True:
            self._chain.append(block)
            for tx in block['data']['transactions']:
                if tx['header']['type'] == 2:
                    for tx_input in tx['data']['inputs']:
                        self._used_transactions[tx_input['tx_id']] = tx['header']['sender']
                self._transactions_map_id[self._crypto.hash(tx['header'])] = tx
            self._blocks_map_id[self._crypto.hash(block['header'])] = block
            return True
        return False

    @property
    def last_block(self):
        return self._chain[-1]


if __name__ == '__main__':
    print("This module is a dependecy")
    exit(0)
