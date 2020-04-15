# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon
This file contains all backend code for my own cryptocurrency named 'reimagined-eureka'
Inspired by code from crankycoin (https://github.com/cranklin/crankycoin/)

I made three classes to make this work:
    1. A Transaction class that deals with all the transactions in the ledger
    2. A Block class that takes a certain amount of transactions to create a block
    3. A BlockChain class that takes multiple blocks with consistent hashes to create a functional blockchain
"""

import json  # need this to convert transaction object into json format
import time  # need to create a timestamp for block object
from multiprocessing import Lock  # need this for threading in blockchain
from pymongo import MongoClient  # need this for storing local blockchain
from mongoengine import *   # I didn't want to use SQL as it's too generic & slow, + I haven't used MongoDB in a while
import security  # need this for...well...everything related to cryptography
from typing import Union, Optional


class Transaction(object):
    def __init__(self, index: int, to: str, amount: int, by: str, fee: int, sign: str, timestamp: float = time.time()):
        """
        The basic unit of any cryptocurrency: a transaction
        Since we want to have some modular features in our transactions, we make it an object
        instead of a simple dict

        We make a quite simple object, with attributes to store the transaction ID(/index), the name of
        sender, receiver, amount, digitally signed text for verification and a hash value of the transaction itself.
        We also create two simple functions: one to generate the hash of transaction and another to get
        the transaction verified, along with another simple __repr__ replacement
        :param index: the index number of every transaction (int)
        :param to: digital sign public key of the person to whom the amount is sent (str)
        :param amount: the amount sent (int)
        :param by: digital sign public key of the person who sent this amount (str)
        :param sign: digital signature of the sender (str)
        """
        self.index = index
        self.sender = by
        self.receiver = to
        self.quantity = amount
        self.fee = fee
        self.timestamp = timestamp
        self.sign = sign
        self.hash = self._get_hash()

    def _get_hash(self) -> str:
        # create a dictionary from instance for json.dumps to work
        transaction = {
            'index': self.index,
            'by': self.sender,
            'amount': self.quantity,
            'to': self.receiver,
            'fee': self.fee,
            'timestamp': self.timestamp,
            'sign': self.sign
        }

        # create json object of this dictionary and get its hash
        data_json = json.dumps(transaction)
        hash_val = security.sha_512(data_json)

        # return the hash value
        return hash_val

    def verify_transaction(self, verification_text: str) -> bool:
        """check if given transaction is verified
        if the transaction is correct, then the digital signature should be valid
        i.e. if we decode the digital signature by the sender's public key,
        it should give us the original text that has been encrypted as the digital signature
        i.e. the verification_text
        :param verification_text: the original text that was encrypted as digital signature (str)
        :return: whether the given digital signature is valid (bool)
        """
        verified = security.decode_their_signature(self.sign, self.sender) == verification_text
        return verified

    def __repr__(self):
        # a replacement for the built-in __repr__() function
        return "Transaction #{}: {} sent {} rEuk to {} (verified)".format(
            self.index, self.sender, self.quantity, self.receiver)


class Block(object):
    # transactions = []

    def __init__(self, height: int, transactions: list, prev_hash: str, timestamp: float = time.time(), nonce: int = 0):
        """
        A simple block class. Each block contains a header which is the hash of the previous block,
        a list of transactions of certain length (or height) and the hash of this block.
        Taking source from crankycoin, I implemented a Merkle Root function for making the header for block,
        however, I did not implement block header as a separate class altogether (force of habit).
        Each block object contains a height parameter, a hash value of previous block
        :param height: height of this block (int)
        :param transactions: list of transactions to be added in the block (list)
        :param prev_hash: hash of previous block (str)
        :param timestamp: timestamp for creation of this block
        :param nonce: initial nonce for this block (int)
        """
        # initialize the attributes
        self.height = height
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.nonce = nonce

        # find the merkle root of the block and make the header based on this merkle root
        self.merkle_root = self._find_merkle_root()
        self.header = self._get_header(self.prev_hash, self.merkle_root, self.timestamp, self.nonce)

        # create the hash value of the block
        self.hash = self._get_hash()

    def _find_merkle_root(self):
        # make sure we have enough transactions
        if len(self.transactions) < 1:
            raise InvalidTransaction(self.height, "Zero transactions in block. Please provide transactions.")

        # create the merkle base
        base = [transaction.hash for transaction in self.transactions]

        # start creating the root
        while len(base) > 1:

            # create temporary base for this run of the loop
            temp_base = []

            # loop over alternate hash value
            for i in range(0, len(base), 2):

                # if we are at the penultimate entry, just get hash of this entry
                if i == len(base) - 1:
                    temp_base.append(security.sha_512(base[i]))

                # otherwise, get hash of this and the next entry merged
                else:
                    temp_base.append(security.sha_512(base[i] + base[i+1]))

            # after every iteration of the loop, the merkle base essentially becomes half
            base = temp_base

        # when we are left with just one final hash, return this value
        return base[0]

    @staticmethod
    def _get_header(prev_hash: str, merkle_root: str, timestamp: float, nonce: int):
        # merge all the data into a utf-8 string and hash it
        data = prev_hash + merkle_root + "{0:0>8x}".format(int(timestamp)) + "{0:0>8x}".format(nonce)
        data_hash = security.sha_512(data + data)

        # this hash value is essentially our block header
        return data_hash

    @property
    def transactions(self) -> list:
        """
        :return: list of transactions in sorted by hash (list)
        """
        if len(self.transactions) <= 1:
            return self.transactions
        base = self.transactions[0]
        transactions_sorted = sorted(self.transactions[1:], key=lambda x: x.hash)
        transactions_sorted.insert(0, base)
        self.transactions = transactions_sorted

    def _get_hash(self) -> str:
        # create a dictionary from instance for json.dumps to work
        block_data = {
            'height': self.height,
            'transactions': self.transactions,
            'header': self.header
        }

        # create json object of this dictionary and get its hash
        data_json = json.dumps(block_data)
        hash_val = security.sha_512(data_json)

        # return the hash value
        return hash_val

    def __repr__(self):
        return "<Block {}>".format(security.sha_512(self.header))

    # I don't understand why I need to set this to get the @property function working but, for some reason,
    # PyCharm keeps insisting that I use this function for the @property function to work...I tried asking
    # on StackOverflow but apparently I've been question-banned there since my previous questions didn't
    # collect much applause on the community (how is it my fault that my questions aren't getting upvotes?
    # Is it not normal to ask questions that might not be relevant to a lot of people?) :/
    @transactions.setter
    def transactions(self, value):
        self._transactions = value


class BlockChain(object):
    # write down chain constants
    INITIAL_COINS = 100
    HALVING_FREQUENCY = 180000
    MAX_TRANSACTIONS = 1000
    HASH_DIFFICULTY_MIN = 2
    TARGET_TIME = 600
    DIFFICULTY_ADJUSTMENT_SPAN = 500
    SIGNIFICANT_DIGITS = 8
    SHORT_CHAIN_TOLERANCE = 3

    def __init__(self):
        self.block_lock = Lock()
        self.database = None
        self.initialize_database()

    def initialize_database(self):
        # make a connection to localhost
        client = MongoClient('mongodb://localhost:27017')

        # register a connection
        # don't need to write `mongoengine.register_connection()` since I imported everything directly
        # so there's no need to call `register_connection()` from inside `mongoengine`
        register_connection(alias='core', name='local_blockchain')

        # make the databases in this client
        self.database = client['database']

        return

    def add_block(self, block: Block) -> None:
        status = False

        # check if we're adding to the tallest branch
        current_branch = self.get_current_branch(block.prev_hash)
        current_height = self.get_height()

        # check if we're at the tallest branch
        if block.height > current_height:
            if current_branch > 0:
                # if the branch we're adding to isn't the primary branch, make it the primary one
                self.change_primary_branch(current_branch)
                current_branch = 0
        else:
            # if we're not on the tallest branch, we need to make a split here
            clashing_branches = self.get_clashing_branches(block.prev_hash)
            if clashing_branches and current_branch in clashing_branches:
                current_branch = self.get_new_branch_id(block.header, block.height)

        # after making sure we're on the correct branch, let's add the data
        # add a block to our block database
        block_entry = self.database.blocks
        entry_data = {'hash': block.header,
                      'previous_hash': block.prev_hash,
                      'merkle_root': block.merkle_root,
                      'height': block.height,
                      'nonce': block.nonce,
                      'timestamp': block.timestamp,
                      'branch': current_branch}
        _ = block_entry.insert_one(entry_data)

        # add all the transactions in this block to our transaction database
        transaction_entry = self.database.transactions
        for transaction in block.transactions:
            entry_data = {'hash': transaction.hash,
                          'by': transaction.sender,
                          'amount': transaction.quantity,
                          'to': transaction.receiver,
                          'fee': transaction.fee,
                          'timestamp': transaction.timestamp,
                          'signature': transaction.sign,
                          'block_hash': block.hash,
                          'branch': current_branch}
            _ = transaction_entry.insert_one(entry_data)

        # we update the height and hash of current branch by looking for the branch ID
        branch_entry = self.database.branch
        to_find = {'_id': current_branch}
        to_update = {'current_height': block.height,
                     'current_hash': block.header}
        _ = branch_entry.update_one(to_find, to_update)

    def get_new_branch_id(self, block_hash: str, height: int):
        # insert a new branch
        branch_entry = self.database.branch
        entry_data = {'current_height': height,
                      'current_hash': block_hash}
        new_branch = branch_entry.insert_one(entry_data)

        # return the ID of this new branch
        return new_branch.inserted_id

    def prune(self) -> str:
        """
        Removes all transactions, blocks and branches that are not a part of the main branch of blockchain
        :return: number of transactions, blocks and branches removed (str)
        """
        # initialize the collections
        blocks_entry = self.database.blocks
        transaction_entry = self.database.transactions
        branch_entry = self.database.branch

        # find the maximum height in the blockchain
        max_height = [x for x in blocks_entry.find().sort('height', -1).limit(1)][0]['height']

        # find the IDs of all branches that have this height
        target_branches = branch_entry.find({'current_height': {
            '$lt': (max_height - self.SHORT_CHAIN_TOLERANCE)}})['_id']

        # find all transactions, blocks and branches that belong to `target_branches`
        tran_block_query = {'branch': {'$in': target_branches}}
        branch_query = {'_id': {'$in': target_branches}}

        # delete all such transactions, blocks and branches
        block_del = blocks_entry.delete_many(tran_block_query)
        transac_del = transaction_entry.delete_many(tran_block_query)
        branch_del = branch_entry.delete_many(branch_query)

        # return the number of transactions, blocks and branches removed
        return f"Cleared {transac_del.deleted_count} transactions, {block_del.deleted_count} blocks, and " \
               f"{branch_del.deleted_count} branches after pruning the blockchain"

    def change_primary_branch(self, branch) -> None:
        # get info of the last block
        new_header, new_branch, new_height = self.get_tallest_block(branch)

        # initialize variables
        alt_hashes = []
        start = new_height
        stop = new_height
        end_of_branch = False

        # start searching
        while not end_of_branch:
            # move one block back
            new_header, new_branch, new_height = self.hash_to_header(new_header.prev_hash)

            # if we're still at the alternate branch, just add this block to the pile
            if new_branch > 0:
                alt_hashes.append(new_header.hash)

            # if we've reached the split point, end our search
            else:
                start = new_height
                end_of_branch = True

        # now that we've found the correct primary branch, fetch headers of all blocks in this branch
        primary_branch = [block[0] for block in self.get_range_of_headers(start, stop, branch=0)]

        # get the database
        block_entry = self.database.blocks
        transaction_entry = self.database.transactions

        # if this block belongs to [originally] alternate branch, shift this to primary branch
        _ = block_entry.update_many({'hash': {'$in': alt_hashes}}, {'branch': 0})

        # if this block belongs to the new alternate branch, shift it to the branch number given
        _ = block_entry.update_many({'hash': {'$in': primary_branch}}, {'branch': branch})

        # same for all the transactions
        _ = transaction_entry.update_many({'block_hash': {'$in': alt_hashes}}, {'branch': 0})
        _ = transaction_entry.update_many({'block_hash': {'$in': primary_branch}}, {'branch': branch})

        # done
        return

    def get_current_branch(self, hash_key: str) -> Union[Optional[int], Block]:
        """
        get the block object from its hash value
        :param hash_key: the hash value to search for in all blocks (str)
        :return: the corresponding block (Block) or 0 if no such block exists (int)
        """
        # get the database
        block_entry = self.database.blocks

        # find the relevant block using the given hash key
        result = block_entry.find({'hash': hash_key})

        # if no such block exists, return 0
        if result.count() == 0:
            return 0

        # return the corresponding block
        return result[0]

    def get_height(self) -> int:
        """
        get the maximum height in the blocks...it works as follows:
            call the collection by self.database.blocks
            get all entries in the collection by .find()
            sort these entries by height in descending order using .sort('height', -1) (-1 specifies descending)
            grab the first entry in this using .limit(1)
            we get a cursor object, which we convert to a list of 1 entry then just one entry by slicing
            this gives us the entry as a dict, from which we retrieve the height value
        """
        return [x for x in self.database.blocks.find().sort('height', -1).limit(1)][0]['height']

    def get_clashing_branches(self, prev_hash: str) -> list:
        # find all blocks that have the given previous hash and return the branch values in those blocks
        return [x['branch'] for x in self.database.blocks.find({'previous_hash': prev_hash}).sort('branch')]

    def get_tallest_block(self, branch: int = 0) -> Union[Optional[None], tuple]:
        # call the collection
        blocks_entry = self.database.blocks

        # find the maximum height (honestly, at this point, I think I should make this a separate function)
        max_height = [x for x in blocks_entry.find().sort('branch', -1).limit(1)][0]['height']

        # find all blocks in this branch, then find the tallest blocks from that list
        # it should be possible to do in a single step, but I'm too lazy to find out how
        block_list = blocks_entry.find({'branch': branch})
        final_block = block_list.find({'height': max_height})

        # if we have no block as tall as we want, return nothing
        if final_block.count() == 0:
            return None

        # otherwise, return its header, branch and height
        return final_block[0]['header'], final_block[0]['branch'], final_block[0]['height']


# initialize exceptions here
class BlockChainException(Exception):
    def __init(self, index, message):
        super(BlockChainException, self).__init__(message)
        self.index = index


class InvalidTransaction(BlockChainException):
    pass
