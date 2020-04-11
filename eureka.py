# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon
This file contains all backend code for my own cryptocurrency named 'reimagined-eureka'
Inspired by code from crankycoin (https://github.com/cranklin/crankycoin/)

I made four classes to make this work:
    1. A Transaction class that deals with all the transactions in the ledger
    2. A Block class that takes a certain amount of transactions to create a block
    3. A BlockChain class that takes multiple blocks with consistent hashes to create a functional blockchain
    4. A Node class that deals the node i.e. the person using this cryptocurrency
"""

import json
import datetime
import random
import security
from typing import Union, Optional


class Transaction:
    def __init__(self, index: int, to: str, amount: int, by: str, sign: str):
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
        self.sign = sign
        self.hash = self.get_hash()

    def get_hash(self) -> str:
        # create a dictionary from instance for json.dumps to work
        transaction = {
            'index': self.index,
            'by': self.sender,
            'amount': self.quantity,
            'to': self.receiver,
            'sign': self.sign
        }

        # create json object of this dictionary and get its hash
        data_json = json.dumps(transaction)
        hash_val = security.sha_512(data_json)

        # return the hash value
        return hash_val

    def verify_transaction(self, verification_text) -> bool:
        # check if given transaction is verified
        # if the transaction is correct, then the digital signature should be valid
        # i.e. if we decode the digital signature by the sender's public key,
        # it should give us the original text that has been encrypted as the digital signature
        # i.e. the verification_text
        verified = security.decode_their_signature(self.sign, self.sender) == verification_text
        return verified

    def __repr__(self):
        # a replacement for the built-in __repr__() function
        return "Transaction #{}: {} sent {} rEuk to {} (verified)".format(
            self.index, self.sender, self.quantity, self.receiver)


# class Block:


# class BlockChain:


# class Node:

