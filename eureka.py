# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon
This file contains all backend code for my own cryptocurrency named 'reimagined-eureka'
Based on code from crankycoin (https://github.com/cranklin/crankycoin/)
"""

import json
import datetime
import random
from eureka_API import API
import security
from typing import Union, Optional


class Node:
    NotImplemented


class Wallet(Node):
    def __init__(self, peers, API, private_key: Union[Optional[tuple], None] = None,
                 public_key: Union[Optional[tuple], None] = None):
        """
        Initialize a wallet object: the interface for client-side
        :param private_key: client private key (int)
        :param public_key: client public key (int)
        """
        # if client already gave key pair, use this key pair
        if private_key is not None and public_key is not None:
            self.__priv_key__ = private_key
            self.__pub_key__ = public_key

        # else, make a default key pair
        self.generate_demo_keys()

        # additional initialization code
        super(Wallet, self).__init__(peers, API)
        self.find_peers()

    def generate_demo_keys(self):
        # if client didn't provide key pair, make one for them
        if self.__priv_key__ is None or self.__pub_key__ is None:
            print("No public and private keys provided! Generating default key pair")

            # see the code in 'security.py' file to know how generate_rsa_key() works
            key_dock = security.generate_rsa_key()
            self.__pub_key__ = key_dock[0], key_dock[1]
            self.__priv_key__ = key_dock[2], key_dock[3]

    def get_pub_key(self):
        return self.__pub_key__

    def get_priv_key(self):
        return self.__priv_key__

    def sign(self, message):
        # sign a transaction using client's private key
        return security.make_your_signature(message, self.__priv_key__)

    def verify_sign(self, sign, message, pub_key=None):
        # if we get a public key, we use it to decode the signature
        if pub_key is not None:
            return security.decode_their_signature(sign, pub_key) == message

        # otherwise, we just use the public key we already have
        return security.decode_their_signature(sign, self.__pub_key__) == message

    def get_balance(self, address=None, node=None):
        # find the current balance of client
        balance = 0

        # make sure we have valid address
        if address is None:
            address = self.get_pub_key()

        # make sure we get valid node
        if node is None:
            # if no node was provided, get all nodes and select any one of them
            peers = self.discover_peers()
            node = random.sample(peers, 1)[0]

        # this algorithm enumerates over all transactions in all blocks
        for block in self.blocks:
            for transaction in block.transactions:
                if transaction['from'] == address:
                    balance -= transaction['amount']
                if transaction['to'] == address:
                    balance += transaction['amount']
        return balance

        # apparently the algorithm implemented in api class works better
        # return self.API.get_balance(address, node)

    # def transaction_history(self, address=None, node=None):
    #     # same as before
    #     if address is None:
    #         address = self.get_pub_key()
    #     if node is None:
    #         peers = self.discover_peers()
    #         node = random.sample(peers, 1)[0]
    #
    #     # we let the api handle these stuff for us
    #     return self.API.transaction_history(address, node)

    def add_transaction(self, to, amount, fee, header):
        # find all peers first
        self.find_peers()

        # create a transaction object
        transaction = Entry(
            self.get_pub_key(),
            to,
            amount,
            fee,
            header,
            hash=0)

        # get it signed
        transaction['sign'] = transaction.sign(self.get_priv_key())
        transaction['hash'] = self.get_transaction_hash(transaction)

        # broadcast this to all nodes
        return self.broadcast(transaction)

    def get_transaction_hash(self, transaction):
        # create a copy of the transaction without hash
        data = transaction.copy()
        data.pop('hash', None)

        # get hash from the json format of data and return it
        data_json = json.dumps(data, sort_keys=True)
        hash_val = security.sha_512(data_json)
        return hash_val


class Transaction:
    def __init__(self, index, to, amount, by, sign):
        self.index = index
        self.sender = by
        self.receiver = to
        self.quantity = amount
        self.sign = sign
        self.get_hash(self)

    @staticmethod
    def get_hash(transaction):
        data_json = json.dumps(transaction)
        hash_val = security.sha_512(data_json)
        return hash_val


class Block:


class BlockChain:


