# -*- coding: utf-8 -*-

from hashlib import sha3_512
import time
import security


class Block:
    def __init__(self, index: int, proof_of_work: int, header: str, data: list, timestamp=None):
        """

        :param index:
        :param proof_of_work:
        :param header:
        :param data:
        :param timestamp:
        """
        self.index = index
        self.proof_of_work = proof_of_work
        self.header = header
        self.data = data
        self.timestamp = timestamp or time.time()

    @property
    def get_hash(self):
        """

        :return:
        """
        pre_hash = "{} {} {} {} {}".format(self.index, self.proof_of_work, self.header, self.data, self.timestamp)
        return sha3_512(pre_hash.encode()).hexdigest()

    def __repr__(self):
        return "Block Index: {}\n" \
               "Proof of Work: {}\n" \
               "Block Header: {}\n" \
               "Block Data: {}\n" \
               "Timestamp: {}\n".format(self.index, self.proof_of_work, self.header, self.data, self.timestamp)


class BlockChain:
    def __init__(self):
        self.chain = []
        self.current_data = []
        self.nodes = set()
        self.starter_function()

    def __repr__(self):
        print(self.chain)
        for data in self.chain[1:]:
            print("rE {} paid by {} to {}\n".format(
                data.data[0]['quantity'], data.data[0]['sender'], data.data[0]['recipient']))
        return str()

    def starter_function(self):
        self.make_a_block(proof_of_work=0, header='0')

    def make_a_block(self, proof_of_work: int, header: str):
        temp_block = Block(
            index=len(self.chain),
            proof_of_work=proof_of_work,
            header=header,
            data=self.current_data)
        self.current_data = []
        self.chain.append(temp_block)
        return temp_block

    @staticmethod
    def proof_verifier(last_proof, proof_of_work):
        """

        :param last_proof:
        :param proof_of_work:
        :return:
        """
        check = f'{last_proof}{proof_of_work}'.encode()
        check_hash = sha3_512(check).hexdigest()
        return check_hash[:4] == "0000"

    @staticmethod
    def check_validity(block_0: Block, prev_block: Block):
        """

        :param block_0:
        :param prev_block:
        :return:
        """
        if block_0.index+1 != prev_block.index:
            return False
        elif prev_block.get_hash != block_0.header:
            return False
        elif not BlockChain.proof_verifier(block_0.proof_of_work, prev_block.proof_of_work):
            return False
        elif block_0.timestamp <= prev_block.timestamp:
            return False

        return True

    @property
    def latest_block(self):
        return self.chain[-1]

    # all methods below are related to block mining
    @staticmethod
    def find_proof(last_proof: int):
        """

        :param last_proof:
        :return:
        """
        proof_of_work = 0
        while BlockChain.proof_verifier(last_proof, proof_of_work) is False:
            proof_of_work += 1
        return proof_of_work

    def add_data(self, by: str, to: str, amount: int, signature: str):
        self.current_data.append({
            'sender': by,
            'recipient': to,
            'quantity': amount,
            'sign': signature
        })
        return True

    def block_mining(self, details_of_miner: dict):
        """

        :param details_of_miner:
        :return:
        """
        self.add_data(by=details_of_miner['sender'], to=details_of_miner['recipient'],
                      amount=details_of_miner['quantity'], signature=details_of_miner['user_key'])
        proof_of_work = self.find_proof(self.latest_block.proof_of_work)
        hash_value = self.latest_block.get_hash
        temp_block = self.make_a_block(proof_of_work, hash_value)
        return vars(temp_block)

    # def add_node(self, address: str):
    #     self.nodes.add(address)
    #     return True

    # @staticmethod
    # def get_block(data: dict):
    #     """
    #
    #     :param data:
    #     :return:
    #     """
    #     return Block(data['index'], data['proof_of_work'], data['header'], data['data'], data['timestamp'])


start = time.time()
blockchain = BlockChain()
print("***Starting rE mining***")
print(blockchain)

print("Blockchain initialized")
your_name = input("Enter Sender's Name: ")
their_name = input("Enter Recipient's Name: ")
money_paid = int(input("Enter Amount to be Paid: "))
if_default_sign = input("Want me to make a default digital signature for you? ")
if if_default_sign == 'yes':
    pub_key = security.generate_rsa_key("default_key_file")
    your_sign = security.make_your_signature(your_name, "default_key_file_private_key.txt")
    with open('default_digital_signature.txt', 'w') as file:
        file.write(your_sign)
    print("Saved a default private key for your digital signature in default_key_file_private_key.txt, "
          "also saved a default digital signature with {} as your name in default_digital_signature.txt, "
          "your public key is {}".format(your_name, pub_key))
else:
    file_path = input("Enter the path of the file containing your digital signature: ")
    your_sign = open(file_path, 'r').readlines()[0]

blockchain.block_mining(
    details_of_miner={
        'sender': your_name,
        'recipient': their_name,
        'quantity': money_paid,
        'user_key': your_sign
    })

print("***Finishing rE mining***")
print(blockchain)
end = time.time()
print("Time elapsed:", end-start)
