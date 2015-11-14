#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, division, absolute_import, unicode_literals
try:  from __builtin__ import bytes, str, open, super, range, zip, round, int, pow, object, input
except ImportError:  pass
try:  from __builtin__ import raw_input as input
except ImportError:  pass


try:
    from .bip38 import simple_aes_encrypt, simple_aes_decrypt, COMPRESSION_FLAGBYTES, LOTSEQUENCE_FLAGBYTES, NON_MULTIPLIED_FLAGBYTES, EC_MULTIPLIED_FLAGBYTES, ILLEGAL_FLAGBYTES, intermediate_code, bip38encrypt, passphrase_to_key, confirm38code, bip38decrypt, addversion, stripversion
except:
    from bip38 import simple_aes_encrypt, simple_aes_decrypt, COMPRESSION_FLAGBYTES, LOTSEQUENCE_FLAGBYTES, NON_MULTIPLIED_FLAGBYTES, EC_MULTIPLIED_FLAGBYTES, ILLEGAL_FLAGBYTES, intermediate_code, bip38encrypt, passphrase_to_key, confirm38code, bip38decrypt, addversion, stripversion

