import json
import re
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
        
        return self._valid_transaction(transaction, service_data)
        
    def _valid_chain(self, chain, service_data):
        if len(chain) <= 1:
            service_data['hight'] = len(chain)
            return True

        service_data['hight'] = 1
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

        if self._crypto.valid_proof(block['header']['data_hash'], block['header']['nonce'], block['header']['difficulty']) == False:
            return False

        for transaction in block['data']['transactions']:
            if self._valid_transaction(transaction, service_data) == False:
                return False
            temp_txs_list[self._crypto.hash(transaction['header'])] = transaction

        service_data['txs_list'].update(temp_txs_list)
        return True

    def _valid_transaction(self, transaction, service_data):
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

        if self._crypto.verify(self._crypto.hash(transaction['data'])
                            , transaction['header']['signature']
                            , transaction['header']['public_key']) == False:
            return False
        
        if transaction['header']['type'] == 1:
            for output_tx in transaction['data']['outputs']:
                if output_tx['amount'] < 0:
                    return False
                if self._valid_address(output_tx['recipient']) is False:
                    return False
                outputs_sum += output_tx['amount']

            if outputs_sum != self._crypto.calculate_reward(service_data['difficulty']):
                return False

        elif transaction['header']['type'] == 2:
            for input_tx in transaction['data']['inputs']:
                # Проверка на то, что входные транзакции действительно были отправлены, совершающему транзакцию
                for tx_out in service_data['txs_list'][input_tx['tx_id']]['data']['outputs']:
                    if tx_out['recipient'] == transaction['header']['sender']:
                        inputs_sum += tx_out['amount']

                # Проверка на то, что транзакции уже не использованы
                full_tx = f"{input_tx['tx_id']}:{transaction['header']['sender']}"
                if full_tx in service_data['used_transactions']:
                    return False
                service_data['used_transactions'].add(full_tx)

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