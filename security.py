# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon
Code from my glowing-robot repository (https://github.com/GoddardGuryon/glowing-robot)
This file is here just to be used at the backend for reimagined-eureka
If you're interested in finding out how the code here works, check out glowing-robot for much more documentation :)
"""

import random
from typing import Union, Optional
import copy
import struct


_BYTE_SIZE = 256
_DEFAULT_BLOCK_SIZE = 128


# following is the code for the RSA-based digital signature program


def rabin_miller_test(n: int) -> bool:
    upper_lim = n - 1
    num_of_times = 0
    while not upper_lim & 1:
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
        return True
    for num in prime_primers:
        if n % num == 0:
            return False
    return rabin_miller_test(n)


def generate_prime(keysize: int = 1024) -> int:
    while True:
        x = random.randrange(2**(keysize-1), 2**keysize)
        if is_this_prime(x):
            return x


def euclid_gcd(x: int, y: int) -> int:
    while x != 0:
        x, y = y % x, x
    return y


def mod_inverse(x: int, y: int) -> Union[Optional[int], None]:
    if euclid_gcd(x, y) != 1:
        return None
    a, b, c, d, e, f = 1, 0, x, 0, 1, y
    while f != 0:
        q = c // f
        d, e, f, a, b, c = (a - q*d), (b - q*e), (c - q*f), d, e, f
    return a % y


def generate_rsa_key(keysize: int = 1024) -> tuple:
    prime_1 = generate_prime(keysize)
    prime_2 = generate_prime(keysize)
    key_1 = prime_1 * prime_2
    while True:
        key_2 = random.randrange(2**(keysize-1), 2**keysize)
        if euclid_gcd(key_2, (prime_1-1)*(prime_2-1)) == 1:
            break
    key_0 = mod_inverse(key_2, (prime_1-1)*(prime_2-1))
    return (key_1, key_2), (key_1, key_0)


def make_your_signature(sign_name: str, private_key: tuple, block_size: int = _DEFAULT_BLOCK_SIZE) -> str:
    n, e = private_key
    sign_in_bytes = sign_name.encode('ascii')
    blocks = []
    for start in range(0, len(sign_in_bytes), block_size):
        block = 0
        for i in range(start, min(start+block_size, len(sign_in_bytes))):
            block += sign_in_bytes[i] * _BYTE_SIZE ** (i % block_size)
        blocks.append(block)
    signature = []
    for block in blocks:
        signature.append(str(pow(block, int(e), int(n))))
    return "{}_{}_{}".format(len(sign_name), block_size, ', '.join(signature))


def decode_their_signature(digital_signature: str, public_key: str) -> str:
    sign_length, block_size, sign_code = digital_signature.split('_')
    blocks = [int(block) for block in sign_code.split(', ')]
    key_1, key_0 = public_key
    decrypted_blocks = [pow(block, int(key_0), int(key_1)) for block in blocks]
    signature = []
    for block in decrypted_blocks:
        block_content = []
        for i in range(int(block_size) - 1, -1, -1):
            if len(signature) + i < int(sign_length):
                block_text = block // (_BYTE_SIZE ** i)
                block = block % (_BYTE_SIZE ** i)
                block_chr = chr(block_text)
                block_content.insert(0, block_chr)
        signature.extend(block_content)
    return "".join(signature)


# Following is the code for SHA512 hash function


def _sha_backend(text_to_hash: str, _buffer: str, _counter: int,
                 _output_size: int, hex_output: bool = False):

    def _rit_rot(on: int, by: int) -> int:
        return ((on >> by) | (on << (64 - by))) & 0xFFFFFFFFFFFFFFFF

    variable_x = _counter & 0x7F
    length = str(struct.pack('!Q', _counter << 3))
    _initial_hashes = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                       0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    _round_constants = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
    if variable_x < 112:
        padding_len = 111 - variable_x
    else:
        padding_len = 239 - variable_x
    text_copy = copy.deepcopy(text_to_hash)
    pad = '\x80' + ('\x00' * (padding_len + 8)) + length
    text_copy += pad[1:]
    _buffer += text_copy
    _counter += len(text_copy)
    if not text_copy:
        return
    if type(text_copy) is not str:
        raise TypeError("Invalid Object! Please enter a valid string for hashing!")
    while len(_buffer) >= 128:
        chunk = _buffer[:128].encode()
        words = [0]*80
        words[:16] = struct.unpack('!16Q', chunk)
        for i in range(16, 80):
            part_1 = _rit_rot(words[i-15], 1) ^ _rit_rot(words[i-15], 8) ^ (words[i-15] >> 7)
            part_2 = _rit_rot(words[i-2], 19) ^ _rit_rot(words[i-2], 61) ^ (words[i-2] >> 6)
            words[i] = (words[i-16] + part_1 + words[i-7] + part_2) & 0xFFFFFFFFFFFFFFFF
            a, b, c, d, e, f, g, h = _initial_hashes
            for z in range(80):
                var_1 = _rit_rot(a, 28) ^ _rit_rot(a, 34) ^ _rit_rot(a, 39)
                var_2 = _rit_rot(e, 14) ^ _rit_rot(e, 18) ^ _rit_rot(e, 41)
                var_3 = (a & b) ^ (a & c) ^ (b & c)
                var_4 = (e & f) ^ ((~e) & g)
                temp_1 = var_1 + var_3
                temp_2 = h + var_2 + var_4 + _round_constants[z] + words[z]
                h, g, f, e = g, f, e, (d + temp_2) & 0xFFFFFFFFFFFFFFFF
                d, c, b, a = c, b, a, (temp_1 + temp_2) & 0xFFFFFFFFFFFFFFFF
                _initial_hashes = [(x + y) & 0xFFFFFFFFFFFFFFFF for x, y in zip(_initial_hashes,
                                                                                [a, b, c, d, e, f, g, h])]
        _buffer = _buffer[128:]
    return_val = [hex(stuff)[2:] for stuff in _initial_hashes[:_output_size]]
    if hex_output is True:
        return_val = [int(stuff, base=16) for stuff in return_val]
        return return_val
    return ''.join(return_val) + return_val[0][0]


def sha_512(text_to_hash: str, hex_digest: bool = False) -> str:
    if not text_to_hash:
        return ""
    if type(text_to_hash) != str:
        text_to_hash = str(text_to_hash)
        raise TypeError("Invalid content! Please provide content in correct format for hashing!")
    _buffer = ''
    _counter = 0
    _output_size = 8
    return _sha_backend(text_to_hash, _buffer, _counter, _output_size, hex_output=hex_digest)
