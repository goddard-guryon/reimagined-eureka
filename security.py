# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon
I tried to implement my own RSA cipher and SHA512 encryption algorithms here, mostly reading about the RSA cipher
from http://inventwithpython.com/hacking/index.html (amazing resource BTW, you must check it out if you're
interested in the contents of this file
"""

import random
import os
import sys


BYTE_SIZE = 256
DEFAULT_BLOCK_SIZE = 128


def rabin_miller_test(n: int) -> bool:
    """
    advanced backend algorithm, finds if given number is prime
    :param n: number to check (int)
    :return: True if n is prime, False otherwise (bool)
    """
    upper_lim = n - 1
    num_of_times = 0
    while not upper_lim & 1:  # while the number is even
        upper_lim = upper_lim // 2
        num_of_times += 1

    for _ in range(5):
        rand_num = random.randrange(2, n-1)
        power = pow(rand_num, upper_lim, n)
        if power != 1:
            i = 0
            while power != n-1:
                if i == (num_of_times-1):
                    return False
                else:
                    i += 1
                    power = (power**2) % n
    return True


def is_this_prime(n: int) -> bool:
    """
    frontend function to find if given number is prime
    :param n: input number (int)
    :return: True if n is prime, False otherwise (bool)
    """
    # some simpler tests before using the advanced function
    prime_primers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
                     101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
                     197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
                     311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
                     431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
                     557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
                     661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
                     809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
                     937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if n < 2:
        return False
    elif n in prime_primers:
        return False
    for num in prime_primers:
        if n % num == 0:
            return False
    # if our simpler tests fail, try the Rabin-Miller primality test
    return rabin_miller_test(n)


def generate_prime(keysize: int = 1024) -> int:
    """
    function to generate a large prime number
    :param keysize: keysize to look the prime number for (int)
    :return: large prime number between 2^(keysize-1) and 2^keysize (int)
    """
    while True:
        x = random.randrange(2**(keysize-1), 2**keysize)
        if is_this_prime(x):
            return x


def euclid_gcd(x: int, y: int) -> int:
    """
    find greatest common divisor of x and y by Euclid's algorithm
    :param x: first number (int)
    :param y: second number (int)
    :return: greatest common divisor (int)
    """
    while x != 0:
        x, y = y % x, x
    return y


def mod_inverse(x: int, y: int) -> int:
    """
    find modular inverse of x with key y
    :param x: number to find modular inverse of (int)
    :param y: key to find x's modular inverse (int)
    :return: modular inverse of x with key y (int)
    """
    if euclid_gcd(x, y) != 1:
        return None
    a, b, c, d, e, f = 1, 0, x, 0, 1, y
    while f != 0:
        q = c // f
        d, e, f, a, b, c = (a - q*d), (b - q*e), (c - q*f), d, e, f
    return a % y


def generate_rsa_key(filename: str, keysize: int = 1024) -> tuple:
    """
    generate public, private key pairs using RSA cipher, save the private key in file of given filename
    :param keysize: keysize to generate key (int)
    :param filename: filename to save private key as (str)
    :return: public, private key pair (int tuple)
    """
    prime_1 = generate_prime(keysize)
    prime_2 = generate_prime(keysize)
    key_1 = prime_1 * prime_2

    while True:
        key_2 = random.randrange(2**(keysize-1), 2**keysize)
        if euclid_gcd(key_2, (prime_1-1)*(prime_2-1)) == 1:
            break

    key_0 = mod_inverse(key_2, (prime_1-1)*(prime_2-1))

    if os.path.exists("{}_private_key.txt".format(filename)):
        sys.exit("Given filename already exists! Please try again with a different file name!")

    with open("{}_private_key.txt".format(filename), 'w') as file:
        file.write("{}\nKeysize: {}".format((key_1, key_0), keysize))

    return key_1, key_2


def make_your_signature(sign_name: str, private_key_filename: str, block_size: int = DEFAULT_BLOCK_SIZE) -> str:
    """
    creates digital signature with person's name using their private key (key is retrieved from file provided
    instead of getting from input directly
    :param sign_name: name of person signing the file (this will be the message encrypted as the signature (str)
    :param private_key_filename: name of the file in which private key is stored [MAKE SURE THIS FILE ONLY CONTAINS
    A SINGLE LINE WITH THE PRIVATE KEY!!! (str)
    :param block_size: the size of blocks made (defaults to 128) (int)
    :return: digital signature as a list of numbers (str)
    """
    # open the file to retrieve the key
    if not os.path.exists(private_key_filename):
        sys.exit("Private Key file not found! Please try again with correct file!")
    file = open(private_key_filename, 'r').readlines()
    n, e = tuple(file[0].strip('\n').strip('(').strip(')').split(", "))

    # create blocks for encryption
    # Fun Fact: encrypting blocks instead of encrypting the whole message is what separates
    # RSA cipher from Caeser cipher or even Affine cipher
    sign_in_bytes = sign_name.encode('ascii')
    blocks = []
    for start in range(0, len(sign_in_bytes), block_size):
        block = 0
        for i in range(start, min(start+block_size, len(sign_in_bytes))):
            block += sign_in_bytes[i] * BYTE_SIZE ** (i % block_size)
        blocks.append(block)

    # encrypt the blocks made above using the key provided
    signature = []
    for block in blocks:
        signature.append(str(pow(block, int(e), int(n))))
    return "{}_{}_{}".format(len(sign_name), block_size, ', '.join(signature))


def decode_their_signature(digital_signature: str, public_key: tuple) -> str:
    """
    decode digital signature based on the public key provided (opposite of make_your_signature() function
    :param digital_signature: digital signature (expects signature in the format made by make_your_signature()) (str)
    :param public_key: public key to decode the signature (str)
    :return: original signature text (str)
    """
    # extract metadata from the digital signature
    sign_length, block_size, sign_code = digital_signature.split('_')

    # create blocks from the signature data
    blocks = [int(block) for block in sign_code.split(', ')]

    # decrypt the blocks
    key_1, key_0 = public_key
    decrypted_blocks = [pow(block, int(key_0), int(key_1)) for block in blocks]

    # convert the blocks to text
    signature = []
    for block in decrypted_blocks:
        block_content = []
        for i in range(int(block_size) - 1, -1, -1):
            if len(signature) + i < int(sign_length):
                block_text = block // (BYTE_SIZE ** i)
                block = block % (BYTE_SIZE ** i)
                block_chr = chr(block_text)
                block_content.insert(0, block_chr)
        signature.extend(block_content)
    return "".join(signature)


"""
USE THIS CODE TO RUN A DEMO OF ALL THE ABOVE FUNCTIONS
message = "Hello, this is the digital signature of Goddard Guryon. " \
          "If you can read this message, it means you have successfully decoded my digital signature. " \
          "Congratulations on having found my signature public key!"
print("Starting with given message...")
pub_key = generate_rsa_key("private_key_demo")
print("Generated public and private keys...public key is: {}".format(pub_key))
sign = make_your_signature(message, "private_key_demo_private_key.txt")
print("Created your digital signature: {}".format(sign))
original = decode_their_signature(sign, pub_key)
print("Finished decoding, ended with:\n {}".format(original))
"""

"""
USE THIS CODE TO DECODE USING A DIGITAL SIGNATURE AND PUBLIC KEY STORED IN SEPARATE FILES
digi_sign = open('default_digital_signature.txt', 'r').readlines()[0]
pub_key = tuple(open(
    'default_key_file_public_key.txt', 'r').readlines()[0].strip('\n').strip('(').strip(')').split(", "))
print(decode_their_signature(digi_sign, pub_key))
"""
