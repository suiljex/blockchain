import re

from bccrypto import BlockchainCrypto


class BlockchainValidator():
    def __init__(self):
        self._crypto = BlockchainCrypto()

    def valid_chain(self, chain):
        local_used_transactions = dict()
        local_transactions_map_id = dict()
        local_blocks_map_id = dict()

        return self._valid_chain(chain, local_blocks_map_id, local_transactions_map_id, local_used_transactions)

    def valid_chain_t(self, blockchain_data):
        chain = blockchain_data['chain']
        local_used_transactions = dict()
        local_transactions_map_id = dict()
        local_blocks_map_id = dict()

        return self._valid_chain(chain, local_blocks_map_id, local_transactions_map_id, local_used_transactions)

    def valid_block_t(self, block, blockchain_data):
        chain = blockchain_data['chain']
        local_used_transactions = dict(blockchain_data['used_txs'])
        local_transactions_map_id = dict(blockchain_data['tx_map_id'])
        local_blocks_map_id = dict(blockchain_data['blk_map_id'])

        return self._valid_block(block, chain, local_blocks_map_id, local_transactions_map_id, local_used_transactions)

    def valid_transaction_t(self, transaction, blockchain_data):
        chain = blockchain_data['chain']
        local_used_transactions = dict(blockchain_data['used_txs'])
        local_transactions_map_id = dict(blockchain_data['tx_map_id'])
        local_blocks_map_id = dict(blockchain_data['blk_map_id'])

        return self._valid_transaction(transaction, chain, local_blocks_map_id, local_transactions_map_id, local_used_transactions)

    def _valid_chain(self, chain, blocks_map_id, transactions_map_id, used_transactions):
        if len(chain) <= 1:
            return True

        blocks_map_id[self._crypto.hash(chain[0]['header'])] = chain[0]

        for block in chain[1:]:
            if self.valid_block_fast(block, chain, local_blocks_map_id, local_transactions_map_id, local_used_transactions) is False:
                return False
            blocks_map_id[self._crypto.hash(block['header'])] = block

        return True

    def _valid_block(self, block, chain, blocks_map_id, transactions_map_id, used_transactions):
        if block['header']['difficulty'] != self._crypto.calculate_difficulty(len(chain)):
            return False
        if block['header']['data_hash'] != self._crypto.hash(block['data']):
            return False
        if self._crypto.valid_proof(block['header']['data_hash'], block['header']['nonce'], block['header']['difficulty']) is False:
            return False
        if block['header']['previous_block'] != self._crypto.hash(blocks_map_id['previous_block']['header']):
            return False
    
        for transaction in block['data']['transactions']:
            if self._valid_transaction(transaction, chain, blocks_map_id, transactions_map_id, used_transactions) is False:
                return False
            transactions_map_id[self._crypto.hash(transaction['header'])] = transaction

        return True

    def _valid_transaction(self, transaction, chain, blocks_map_id, transactions_map_id, used_transactions):
        if type(transaction) != type(dict()):
            return False
        if list(transaction.keys()).sort() != ['header', 'data'].sort():
            return False
        if list(transaction['header'].keys()).sort() != ['type', 'sender', 'public_key', 'signature'].sort():
            return False
        if transaction['header']['type'] == 2 and list(transaction['data'].keys()).sort() != ['inputs', 'outputs'].sort():
            return False
        if transaction['header']['type'] == 1 and list(transaction['data'].keys()).sort() != ['outputs'].sort():
            return False
        for tx_output in transaction['data']['outputs']:
            if list(tx_output.keys()).sort() != ['reciever', 'amount'].sort():
                return False
        if transaction['header']['type'] == 2:
            for tx_input in transaction['data']['outputs']:
                if list(tx_input.keys()).sort() != ['tx_id'].sort():
                    return False

        inputs_sum = 0
        outputs_sum = 0

        if transaction['header']['sender'] != self._crypto.generate_address(transaction['header']['public_key']):
            return False

        if self._crypto.verify(self._crypto.hash(transaction['data']),
                               transaction['header']['signature'],
                               transaction['header']['public_key']) is False:
            return False

        if transaction['header']['type'] == 1:
            for output_tx in transaction['data']['outputs']:
                if output_tx['amount'] < 0:
                    return False
                if self._valid_address(output_tx['recipient']) is False:
                    return False
                outputs_sum += output_tx['amount']

            if outputs_sum != self._crypto.calculate_reward(len(chain)):
                return False

        elif transaction['header']['type'] == 2:
            for input_tx in transaction['data']['inputs']:
                # Проверка на то, что входные транзакции действительно были отправлены, совершающему транзакцию
                for tx_out in transactions_map_id[input_tx['tx_id']]['data']['outputs']:
                    if transaction['header']['sender'] == tx_out['recipient']:
                        inputs_sum += tx_out['amount']
                        
                # Проверка на то, что транзакции уже не использованы
                if transaction['header']['sender'] in used_transactions[input_tx['tx_id']]:
                    return False
                used_transactions[input_tx['tx_id']] = transaction['header']['sender']
                
            for output_tx in transaction['data']['outputs']:
                if output_tx['amount'] < 0:
                    return False
                if self._valid_address(output_tx['recipient']) is False:
                    return False
                outputs_sum += output_tx['amount']

            if inputs_sum != outputs_sum:
                return False
        return True

    def _valid_address(self, address):
        regex = re.compile('[a-f0-9]{64}')
        match = regex.match(address)
        return bool(match)


if __name__ == '__main__':
    print("This module is a dependecy")
    exit(0)
