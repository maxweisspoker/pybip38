# pybip38
My python implementation of the full BIP0038 spec

Requires:  pycrypto, scrypt, simplebitcoinfuncs

BIP:  https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

When in doubt, use normalized unicode input for passwords with non-standard characters.

For example:

    u'\u03D2\u0301\u0000\U00010400\U0001F4A9'


### Functions

Encrypt/Decrypt via password:

    bip38encrypt(password, priv, iscompressed=False)
        # Compression bool is ignored if private key input is WIF

    bip38decrypt(password, encpriv, outputlotsequence=False)
        # Returns WIF key str if decrypted, else False
        # Returns tuple of (key, lot_int, sequence_int) if third input bool is True
        # Returns (key, False, False) if lot and sequence arne't used
        # and (False, False, False) if decryption fails.

EC Multiplied keys:

    intermediate_code(password, useLotAndSequence=False, lot=100000, sequence=1, owner_salt=os.urandom(8))
        # returns 'passphrase' string intermediate code

    passphrase_to_key(intermediatecode, iscompressed=False, seedb=os.urandom(24))
        # Takes 'passphrase' string as input
        # Returns tuple of:
        # (6P_encryptedkey_str, cfrm38_str, address_str)
        # seedb default is actually doublesha256(os.urandom(40))[:24]
        ########
        # It is recommended to leave iscompressed to False, since the
        # Bitcoin Address Utility reference implementation does NOT
        # confirm cfrm38 codes for compressed keys. It can still
        # decrypt the 6P key just fine, but the confirmation code
        # won't validate. My Python code here does validate them.

    confirm38code(password, cfrm38code, outputlotsequence=False)
        # Returns Bitcoin address if confirmed, else False
        # Optionally returns lot and sequence also, following
        # same rules as outline in bip38decrypt() info above.

Version Bytes:

    addversion(encpriv, version='80')
        # Takes 6P_key_str in and changes it to begin with 6V, and encodes a version byte.
        # This allows alt-coins to be differentiated.
        # This is a novelty function available ONLY HERE and is NOT part of the BIP0038 specification.
        # Nobody else uses this! You have been warned!!!

    stripversion(6V_key_str, outputversion=False)
        # Returns 6P key str, or tuple of (6P-key, 2-char-hexstr-version-byte)


##Installation

Make sure you have the requirements satisfied, then

    sudo pip install pybip38

