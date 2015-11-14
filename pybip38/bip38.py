#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, division, absolute_import, unicode_literals
try:  from __builtin__ import bytes, str, open, super, range, zip, round, int, pow, object, input
except ImportError:  pass
try:  from __builtin__ import raw_input as input
except ImportError:  pass

import os
import sys
import hashlib
import scrypt
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from simplebitcoinfuncs import *
from simplebitcoinfuncs.hexhashes import *
from simplebitcoinfuncs.ecmath import N


def simple_aes_encrypt(msg,key):
    assert len(key) == 32
    assert len(msg) == 16
    msg = hexstrlify(msg) # Stupid hack/workaround for ascii decode errors
    msg = msg + '7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b'
    cipher = AES.new(key)
    return cipher.encrypt(unhexlify(msg))[:16]

def simple_aes_decrypt(msg,key):
    assert len(msg) == 16
    assert len(key) == 32
    cipher = AES.new(key)
    msg = hexstrlify(cipher.decrypt(msg))
    while msg[-2:] == '7b': # Can't use rstrip for multiple chars
        msg = msg[:-2]
    for i in range((32 - len(msg))//2):
        msg = msg + '7b'
    assert len(msg) == 32
    return unhexlify(msg)

COMPRESSION_FLAGBYTES = ['20','24','28','2c','30','34','38','3c','e0','e8','f0','f8']
LOTSEQUENCE_FLAGBYTES = ['04','0c','14','1c','24','2c','34','3c']
NON_MULTIPLIED_FLAGBYTES = ['c0','c8','d0','d8','e0','e8','f0','f8']
EC_MULTIPLIED_FLAGBYTES = ['00','04','08','0c','10','14','18','1c','20','24','28','2c','30','34','38','3c']
ILLEGAL_FLAGBYTES = ['c4','cc','d4','dc','e4','ec','f4','fc']

def intermediate_code(password,useLotAndSequence=False,lot=100000,sequence=1, \
                      owner_salt=os.urandom(8)):
    '''
    Generates an intermediate code, as outlined by the BIP0038
    wiki, found at:

    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

    Output is a string, beginning with 'passphrase'. Lot and
    sequence inputs are ints.  Even though the Lot range is only
    recommended to be in the range 100000-999999, that
    recommendation is enforced in this code. Sequence is in the
    range 0-4095. Sequence starts at one instead of zero, as per
    the wiki recommendation.

    Also, note that the wiki test vectors do not include examples
    for compressed keys with EC multiplication. Nor does the 
    Bitcoin Address Utility reference implementation successfully
    identify 'cfrm38' confirmation codes for compressed keys.
    This python implementation works with them, and the Bitcoin
    Address Utility can still decrypt the '6P' encrypted private
    keys for compressed public keys, but for compatibility with
    the reference implementation, it is highly recommended that
    you create encrypted keys and confirmation codes only for
    uncompressed public keys when using an intermediate code to
    create EC multiplied encryped private keys with confirmation
    codes.
    '''

    password = normalize_input(password, False, True)
    assert len(owner_salt) == 8 or \
          (len(owner_salt) == 4 and useLotAndSequence)
    if useLotAndSequence:
        lot, sequence = int(lot), int(sequence)
        assert lot >= 100000 and lot <= 999999
        assert sequence >= 0 and sequence <= 4095
        lotsequence = dechex((lot*4096 + sequence),4)
        owner_salt = owner_salt[:4]
        prefactor = scrypt.hash(password,owner_salt,16384,8,8,32)
        prefactor = hexstrlify(prefactor)
        owner_entropy = hexstrlify(owner_salt) + lotsequence
        passfactor = hash256(prefactor + owner_entropy)
        magicbytes = '2ce9b3e1ff39e251'
    else:
        passfactor = scrypt.hash(password,owner_salt,16384,8,8,32)
        passfactor = hexstrlify(passfactor)
        owner_entropy = hexstrlify(owner_salt)
        magicbytes = '2ce9b3e1ff39e253'
    passpoint = privtopub(passfactor,True)
    return b58e(magicbytes + owner_entropy + passpoint)

def bip38encrypt(password,priv,iscompressed=False):
    '''
    Use BIP0038 wiki specification to encrypt a private key with a
    given password (the non-EC multiplication method).

    See the wiki for more information:
    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

    iscompressed flag ignored if private key input is WIF (and WIF
    dictates compression).
    '''

    password = normalize_input(password, False, True)
    try:
        priv, prefix, iscompressed = wiftohex(priv)
    except:
        priv = privtohex(priv)
    prefix = '0142' # Not using EC multiplication
    if iscompressed:
        flagbyte = 224
    else:
        flagbyte = 192
    flagbyte = dechex(flagbyte)
    pubkey = privtopub(priv,iscompressed)
    address = pubtoaddress(pubkey,'00')
    try: addrhex = hexstrlify(address)
    except: addrhex = hexstrlify(bytearray(address,'ascii'))
    salt = unhexlify(hash256(addrhex)[:8])
    scrypthash = hexstrlify(scrypt.hash(password,salt,16384,8,8,64))
    msg1 = dechex((int(priv[:32],16) ^ int(scrypthash[:32],16)),16)
    msg2 = dechex((int(priv[32:],16) ^ int(scrypthash[32:64],16)),16)
    msg1, msg2 = unhexlify(msg1), unhexlify(msg2)
    key = unhexlify(scrypthash[64:])
    half1 = hexstrlify(simple_aes_encrypt(msg1,key))
    half2 = hexstrlify(simple_aes_encrypt(msg2,key))
    salt = hexstrlify(salt)
    return b58e(prefix + flagbyte + salt + half1 + half2)

def passphrase_to_key(intermediatecode,iscompressed=False, \
      seedb = hashlib.sha256(hashlib.sha256(os.urandom(40)).digest()).digest()[:24]):

    '''
    Use BIP0038 wiki specification to generate an encrypted private
    key from an intermeiate code. Input should be str beginning
    with 'passphrase'.

    Returns a tuple of three outputs. First output is the base58
    encoded encrypted private key, a str beginning with '6P'.
    Seoncd output is the cfrm38 code, also a str. Third output is
    the public Bitcoin address.

    As noted in the intermediate_code() __doc__, the wiki test
    vectors do not include examples for compressed EC multiplied
    encrypted keys, and the Bitcoin Address Utility reference
    implementation does not recognize cfrm38 confirmation codes
    for compressed keys. So if you are using an intermediate code
    to generate an EC multiplied key, for compatibility purposes it
    strongly recommended that you use the uncompressed flagbyte.
    That is why the iscompressed variable is defaulted to False.

    That being said, this implementation has no trouble verifying
    compressed confirmation codes, and the Bitcoin Address Utility
    can still properly decrypt the '6P' encrypted private keys for
    compressed keys, even though the confirmation code fails
    to verify.

    See the wiki for more information:
    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
    '''

    intermediatecode = normalize_input(intermediatecode)
    assert intermediatecode[:10] == 'passphrase'
    intermediatecode = b58d(intermediatecode)
    assert intermediatecode[:4] == '2ce9'
    assert len(intermediatecode) == 98
    assert intermediatecode[14:16] == '51' or intermediatecode[14:16] == '53'
    prefix = '0143' # Using EC multiplication
    if iscompressed:
        flagbyte = 32
    else:
        flagbyte = 0
    magicbytes = intermediatecode[:16]
    owner_entropy = intermediatecode[16:32]
    passpoint = intermediatecode[32:]
    if intermediatecode[14:16] == '51':
        flagbyte += 4
    flagbyte = dechex(flagbyte)
    seedb = hexstrlify(seedb)
    factorb = hash256(seedb)
    assert int(factorb,16) > 0 and int(factorb,16) < N
        # Use a new seedb if this assertion fails
        # It is just random horrendously bad luck if this happens.
    newkey = multiplypub(passpoint,factorb,iscompressed)
    address = pubtoaddress(newkey,'00')
    try: addrhex = hexstrlify(address)
    except: addrhex = hexstrlify(bytearray(address,'ascii'))
    addresshash = hash256(addrhex)[:8]
    salt = unhexlify(addresshash + owner_entropy)
    passpoint = unhexlify(passpoint)
    scrypthash = hexstrlify(scrypt.hash(passpoint,salt,1024,1,1,64))
    msg1 = dechex(int(seedb[:32],16) ^ int(scrypthash[:32],16),16)
    key = unhexlify(scrypthash[64:])
    half1 = hexstrlify(simple_aes_encrypt(unhexlify(msg1),key))
    msg2 = dechex(int(half1[16:] + seedb[32:],16) ^ int(scrypthash[32:64],16),16)
    half2 = hexstrlify(simple_aes_encrypt(unhexlify(msg2),key))
    enckey = b58e(prefix + flagbyte + addresshash + owner_entropy + \
                  half1[:16] + half2)
    pointb = privtopub(factorb,True)
    pointb_prefix = (int(scrypthash[126:],16) & 1) ^ int(pointb[:2],16)
    pointb_prefix = dechex(pointb_prefix)
    msg3 = int(pointb[2:34],16) ^ int(scrypthash[:32],16)
    msg4 = int(pointb[34:],16) ^ int(scrypthash[32:64],16)
    msg3 = unhexlify(dechex(msg3,16))
    msg4 = unhexlify(dechex(msg4,16))
    pointb_half1 = hexstrlify(simple_aes_encrypt(msg3,key))
    pointb_half2 = hexstrlify(simple_aes_encrypt(msg4,key))
    encpointb = pointb_prefix + pointb_half1 + pointb_half2
    cfrm38code = b58e('643bf6a89a' + flagbyte + addresshash + \
                      owner_entropy + encpointb)
    return enckey, cfrm38code, address

def confirm38code(password,cfrm38code,outputlotsequence=False):
    '''
    Returns a bitcoin address if the cfrm38 code is confirmed, or
    False if the code does not confirm. As mentioned elsewhere, the
    official BIP0038 draft test vectors do not includes EC multiplied
    keys and confirmation codes for compressed public keys, and the
    Bitcoin Address Utility reference implementation does not validate
    confirmation codes for compressed addresses, so for compatability
    purposes, it is strongly recommended that you create uncompressed
    EC multiplied keys and confirmation codes when creating them with
    this library. This library has no problem creating or validating
    compressed keys, so the option is still available, it is just set
    to uncompressed keys by default.

    outputlotsequence bool is whether or not to return lot and
    sequence numbers with the output, assuming the confirmation code
    is valid. If it is set to True, but the flagbyte indicates lot
    and sequence are not used, then this method will return False for
    both the lot and sequence outputs. e.g. (False, False, False) for
    the output of this method.

    WARNING: Do not use 'if lot' or 'if sequence' to determine if
    they are False or not, since they may be the integer zero.
    '''

    password = normalize_input(password, False, True)
    cfrm38code = b58d(cfrm38code)
    assert len(cfrm38code) == 102
    assert cfrm38code[:10] == '643bf6a89a'
    flagbyte = cfrm38code[10:12]
    addresshash = cfrm38code[12:20]
    owner_entropy = cfrm38code[20:36]
    encpointb = cfrm38code[36:]
    if flagbyte in LOTSEQUENCE_FLAGBYTES:
        owner_salt = owner_entropy[:8]
        lotsequence = owner_entropy[8:]
    else:
        lotsequence = False
        owner_salt = owner_entropy
    owner_salt = unhexlify(owner_salt)
    prefactor = hexstrlify(scrypt.hash(password,owner_salt,16384,8,8,32))
    if flagbyte in LOTSEQUENCE_FLAGBYTES:
        passfactor = hash256(prefactor + owner_entropy)
    else:
        passfactor = prefactor
    if int(passfactor,16) == 0 or int(passfactor,16) >= N:
        if outputlotsequence:
            return False, False, False
        else:
            return False
    passpoint = privtopub(passfactor,True)
    password = unhexlify(passpoint)
    salt = unhexlify(addresshash + owner_entropy)
    scrypthash = hexstrlify(scrypt.hash(password,salt,1024,1,1,64))
    msg1 = unhexlify(encpointb[2:34])
    msg2 = unhexlify(encpointb[34:])
    key = unhexlify(scrypthash[64:])
    half1 = simple_aes_decrypt(msg1,key)
    half2 = simple_aes_decrypt(msg2,key)
    half1, half2 = hexstrlify(half1), hexstrlify(half2)
    pointb_half1 = int(half1,16) ^ int(scrypthash[:32],16)
    pointb_half2 = int(half2,16) ^ int(scrypthash[32:64],16)
    pointb_xcoord = dechex(pointb_half1,16) + dechex(pointb_half2,16)
    pointb_prefix = int(encpointb[:2],16) ^ (int(scrypthash[126:],16) & 1)
    pointb = dechex(pointb_prefix,1) + pointb_xcoord
    newkey = multiplypub(pointb,passfactor,False)
    if flagbyte in COMPRESSION_FLAGBYTES:
        newkey = compress(newkey)
    address = pubtoaddress(newkey,'00')
    try: addrhex = hexstrlify(address)
    except: addrhex = hexstrlify(bytearray(address,'ascii'))
    addresshash2 = hash256(addrhex)[:8]
    if addresshash == addresshash2:
        if outputlotsequence:
            if lotsequence is not False:
                lotsequence = int(lotsequence,16)
                sequence = lotsequence % 4096
                lot = (lotsequence - sequence) // 4096
                return address, lot, sequence
            else:
                return address, False, False
        else:
            return address
    else:
        if outputlotsequence:
            return False, False, False
        else:
            return False

def bip38decrypt(password,encpriv,outputlotsequence=False):
    '''
    Decrypts a BIP0038 encrypted key. If outputlotsequence is True,
    it returns lot and sequence numbers as well, or False if lot
    and sequence numbers aren't used or the password is incorrect.
    The key output will be False if the password is incorrect.

    So sample outputs for outputlotsequence=True might be:
    ('5JPnPNvEz5k1EGuq85MA8ria13TE9vZfpDH8eKQiRumgbz75FGb', 206938, 1)
    ('5JPnPNvEz5k1EGuq85MA8ria13TE9vZfpDH8eKQiRumgbz75FGb', False, False)
    (False, False, False)

    Or if outputlotsequence=False:
    '5JPnPNvEz5k1EGuq85MA8ria13TE9vZfpDH8eKQiRumgbz75FGb'
    or:
    False

    WARNING: Do not use 'if lot' or 'if sequence' to determine if
    they are False or not, since they may be the integer zero.
    '''

    password = normalize_input(password, False, True)
    encpriv = b58d(encpriv)
    assert len(encpriv) == 78
    prefix = encpriv[:4]
    assert prefix == '0142' or prefix == '0143'
    flagbyte = encpriv[4:6]
    if prefix == '0142':
        salt = unhexlify(encpriv[6:14])
        msg1 = unhexlify(encpriv[14:46])
        msg2 = unhexlify(encpriv[46:])
        scrypthash = hexstrlify(scrypt.hash(password,salt,16384,8,8,64))
        key = unhexlify(scrypthash[64:])
        msg1 = hexstrlify(simple_aes_decrypt(msg1,key))
        msg2 = hexstrlify(simple_aes_decrypt(msg2,key))
        half1 = int(msg1,16) ^ int(scrypthash[:32],16)
        half2 = int(msg2,16) ^ int(scrypthash[32:64],16)
        priv = dechex(half1,16) + dechex(half2,16)
        if int(priv,16) == 0 or int(priv,16) >= N:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        pub = privtopub(priv,False)
        if flagbyte in COMPRESSION_FLAGBYTES:
            privcompress = '01'
            pub = compress(pub)
        else:
            privcompress = ''
        address = pubtoaddress(pub,'00')
        try: addrhex = hexstrlify(address)
        except: addrhex = hexstrlify(bytearray(address,'ascii'))
        addresshash = hash256(addrhex)[:8]
        if addresshash == encpriv[6:14]:
            priv = b58e('80' + priv + privcompress)
            if outputlotsequence:
                return priv, False, False
            else:
                return priv
        else:
            if outputlotsequence:
                return False, False, False
            else:
                return False
    else:
        owner_entropy = encpriv[14:30]
        enchalf1half1 = encpriv[30:46]
        enchalf2 = encpriv[46:]
        if flagbyte in LOTSEQUENCE_FLAGBYTES:
            lotsequence = owner_entropy[8:]
            owner_salt = owner_entropy[:8]
        else:
            lotsequence = False
            owner_salt = owner_entropy
        salt = unhexlify(owner_salt)
        prefactor = hexstrlify(scrypt.hash(password,salt,16384,8,8,32))
        if lotsequence is False:
            passfactor = prefactor
        else:
            passfactor = hash256(prefactor + owner_entropy)
        if int(passfactor,16) == 0 or int(passfactor,16) >= N:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        passpoint = privtopub(passfactor,True)
        password = unhexlify(passpoint)
        salt = unhexlify(encpriv[6:14] + owner_entropy)
        encseedb = hexstrlify(scrypt.hash(password,salt,1024,1,1,64))
        key = unhexlify(encseedb[64:])
        tmp = hexstrlify(simple_aes_decrypt(unhexlify(enchalf2),key))
        enchalf1half2_seedblastthird = int(tmp,16) ^ int(encseedb[32:64],16)
        enchalf1half2_seedblastthird = dechex(enchalf1half2_seedblastthird,16)
        enchalf1half2 = enchalf1half2_seedblastthird[:16]
        enchalf1 = enchalf1half1 + enchalf1half2
        seedb = hexstrlify(simple_aes_decrypt(unhexlify(enchalf1),key))
        seedb = int(seedb,16) ^ int(encseedb[:32],16)
        seedb = dechex(seedb,16) + enchalf1half2_seedblastthird[16:]
        assert len(seedb) == 48 # I want to except for this and be alerted to it
        try:
            factorb = hash256(seedb)
            assert int(factorb,16) != 0
            assert not int(factorb,16) >= N
        except:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        priv = multiplypriv(passfactor,factorb)
        pub = privtopub(priv,False)
        if flagbyte in COMPRESSION_FLAGBYTES:
            privcompress = '01'
            pub = compress(pub)
        else:
            privcompress = ''
        address = pubtoaddress(pub,'00')
        try: addrhex = hexstrlify(address)
        except: addrhex = hexstrlify(bytearray(address,'ascii'))
        addresshash = hash256(addrhex)[:8]
        if addresshash == encpriv[6:14]:
            priv = b58e('80' + priv + privcompress)
            if outputlotsequence:
                if lotsequence is not False:
                    lotsequence = int(lotsequence,16)
                    sequence = lotsequence % 4096
                    lot = (lotsequence - sequence) // 4096
                    return priv, lot, sequence
                else:
                    return priv, False, False
            else:
                return priv
        else:
            if outputlotsequence:
                return False, False, False
            else:
                return False

def addversion(encpriv,version='80'):
    '''
    Adds a version byte to a BIP0038 encrypted key and changed the
    prefix from 6P to 6V. This way, alt-coin keys can be
    differentiated from Bitcoin keys.

    This is a novelty function created and used only in this library.
    It is not used or supported anywhere else. You have been warned!
    '''

    encpriv = b58d(encpriv)
    version = hexstrlify(unhexlify(version))
    assert len(version) == 2
    assert len(encpriv) == 78
    assert encpriv[:4] == '0142' or encpriv[:4] == '0143'

    if encpriv[:4] == '0142':
        newprefix = '10df'
    else:
        newprefix = '10e0'
    # The range for retaining the '6V' prefix is 0x10dd to 0x10e9.
    # Currently, the stripversion() function assumes 10d[d-f] to be
    # 0142 and 10e[0-9] to be 0143, and it does not check the last
    # hex char. It only looks for 10d or 10e.

    return b58e(newprefix + version + encpriv[4:])

def stripversion(encpriv,outputversion=False):
    '''
    Strips the version byte added by the previous function, and
    returns the original 6P encrypted key. Optionally, also returns
    the version byte.
    '''

    encpriv = b58d(encpriv)
    assert encpriv[:3] == '10d' or encpriv[:3] == '10e'
    assert len(encpriv) == 80
    if encpriv[:3] == '10d':
        prefix = '0142'
    else:
        prefix = '0143'
    version = encpriv[4:6]
    if outputversion:
        return b58e(prefix + encpriv[6:]), version
    else:
        return b58e(prefix + encpriv[6:])

