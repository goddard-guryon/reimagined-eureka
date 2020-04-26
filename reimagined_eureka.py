# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon

This file contains the code for the interface to the blockchain. In its current state, it contains only
a demo_everything() function that runs a local blockchain on your command line and lets you add some dummy
transactions into it. Once this part is fully implemented, this file will contain a PyQt5 implementation of
the interface to this blockchain that also connects with MongoDB in the background.
"""

import socket
import subprocess
import random
import time
import security
import eureka


def start_mongo():
    try:
        # try starting as normal user
        subprocess.check_output(['mongod', '--quiet'])
        return True
    except subprocess.CalledProcessError as error:

        # if terminal requires us to be super user
        if error.returncode == 100:
            import getpass

            # fetch password
            pass_call = subprocess.Popen(['echo', 'AGEarth1295;'], stdout=subprocess.PIPE)

            # run the service as super user
            process = subprocess.Popen(['sudo', 'mongod', '--quiet'],
                                       stdin=pass_call.stdout,
                                       stdout=subprocess.PIPE)
            return process.returncode


def stop_mongo():
    # stop the service as super user
    process = subprocess.Popen(['sudo', 'mongod', '--shutdown'],
                               stdout=subprocess.PIPE)
    return process.returncode


def demo_everything():
    # see if MongoDB service is already active

    # if it is working, we should be able to connect at '127.0.0.1:27017'
    service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    status = service.connect_ex(('127.0.0.1', 27017))
    if status != 0:

        # MongoDB service is not active, start it from here
        print("Starting MongoDB service...")
        start_code = start_mongo()
        print("MongoDB started with code {}\n".format(start_code))
        need_to_end_service = True
    else:

        # MongoDB service is already working, we need not do anything
        need_to_end_service = False

    # Greet
    print("Welcome to the command line interface of reimagined-eureka!\n")
    defaults = False

    # equivalent of asking your name
    by = input("To register, enter your digital signature public key: ")

    # if you don't enter your name, we'll register you as guest
    if len(by) <= 0:
        print("No public key provided! Creating default digital signature key...\n")

        # still need to encrypt SOMETHING into your digital signature
        sign_text = input("Enter text to make digital signature of: ")
        pub_key, priv_key = security.generate_rsa_key()
        default_sign = security.make_your_signature(sign_text, priv_key)
        defaults = True
        print("Created default digital signature\n")

    # how long our block will be
    num_trans = int(input("How many transactions do you want to add? "))
    transactions = []

    # if you are a guest, we already have some of your details
    if defaults:
        for trans in range(num_trans):
            print("\nTransaction #{}:\n".format(trans+1))
            to = input("Enter the digital signature public key of the person you are sending this to: ")
            amount = float(input("Enter the amount you want to send: "))
            # noinspection PyUnboundLocalVariable
            transactions.append(eureka.Transaction(trans, to, amount, pub_key, random.randint(1, 10),
                                                   default_sign, time.time()))
    else:
        # if you're not a guest, you need to fill those details manually
        for trans in range(num_trans):
            print("\nTransaction #{}:\n".format(trans+1))
            to = input("Enter the digital signature public key of the person you are sending this to: ")
            amount = float(input("Enter the amount you want to send: "))
            sign = input("Enter your digital signature: ")
            transactions.append(eureka.Transaction(trans, to, amount, by, random.randint(1, 10), sign, time.time()))

    # initialize the blockchain
    print("\nInitializing the blockchain...\n")
    blockchain = eureka.BlockChain()

    # get the hash of the genesis block
    first_hash = blockchain.database.blocks.find({'timestamp': 0})[0]['hash']

    # create a block of the transactions you just made
    print("Adding your transactions into blocks...\n")
    block = eureka.Block(num_trans, transactions, first_hash, time.time())
    print("Adding block into the chain...\n")
    blockchain.add_block(block)

    # print the final blockchain
    print("\n\nBlockchain:\n")
    for chain in blockchain.__repr__():
        print(chain)
    print("Exiting...")

    # exit

    # close the connection first
    assert blockchain.close_connection() is None
    # if we started the MongoDB service, we will close it here
    if need_to_end_service:
        end_code = stop_mongo()
        print("Finished demo with code {}".format(end_code))
    else:

        # the service was already working, we need not do anything
        print("Finished demo!")


demo_everything()
