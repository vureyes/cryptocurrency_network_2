# As usual, most of the code is stolen from Jimmy Song's book, I just made it worse

# This implementation supports the following:
#   Evaluation of scripts: only p2pk and p2pkh
#   Creating transactions: anything with p2pk, p2pkh
#   Creating transactions: sendo to a p2sh address (but not the spend)


from io import BytesIO
from unittest import TestCase

import json
import requests

from ecc import PrivateKey
from base58 import *
from scriptSimplified import *


# This method connects to a full node to receive a transaction in order to later validate it
# The API we're using is a bit weird, but you can try with another one if you prefer
class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            # make sure the tx we got matches to the hash we requested
            if raw[4] == 0:
                # zero imputs = coinbase
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
#            if tx.id() != tx_id:
#                raise ValueError('not the same id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)

'''
# The transaction class
'''
class Tx:

    '''
    What defines a transaction:
    1. Version
    2. Locktime
    3. Inputs
    4. Outputs
    5. Network (testnet or not)
    '''
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    # As usual, our prettyprint for printing the transaction; nothing interesting here
    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    # Transaction ID; this is our hash pointer in the UTXO set
    # I.e. when you ask for a transaction to a full node, it guards it under this key
    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    # Well, just the hash
    # Note that the hash is given in "little-endian"
    def hash(self):
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize())[::-1]

    # When we receive raw transaction (bytes) we want to parse it to figure out what's what
    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version is an integer in 4 bytes, little-endian
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # parse num_inputs number of TxIns
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # parse num_outputs number of TxOuts
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is an integer in 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    # When we have a transaction object, to send it to the network we need to serialize it
    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    # Computes the transaction fee
    # Recall that this will need to connect to a full node to get the input transaction!!!
    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # use TxIn.value() to sum up the input amounts
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        # use TxOut.amount to sum up the output amounts
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        # fee is input sum - output sum
        return input_sum - output_sum

    # Here we compute the serialization of what will be signed in a transaction
    def sig_hash(self, input_index):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # if input_index is not in tx_ins, then all ScriptSigs will be empty!!!
        # start the serialization with version
        # use int_to_little_endian in 4 bytes
        s = int_to_little_endian(self.version, 4)
        # add how many inputs there are using encode_varint
        s += encode_varint(len(self.tx_ins))
        # loop through each input using enumerate, so we have the input index
        for i, tx_in in enumerate(self.tx_ins):
            # if the input index is the one we're signing
            if i == input_index:
                # Get the script_pubkey from the output being spent
                script_sig = tx_in.script_pubkey(self.testnet)
            # Otherwise, the ScriptSig is empty
            else:
                script_sig = None
            # add the serialization of the input with the ScriptSig we want
            s += TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            ).serialize()
        # add how many outputs there are using encode_varint
        s += encode_varint(len(self.tx_outs))
        # add the serialization of each output
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        # add the locktime using int_to_little_endian in 4 bytes
        s += int_to_little_endian(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        s += int_to_little_endian(SIGHASH_ALL, 4)
        # hash256 the serialization
        h256 = hash256(s)
        # convert the result to an integer using int.from_bytes(x, 'big')
        # this is because we sign a scalar (recall ecc implementation)
        return int.from_bytes(h256, 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # grab the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)

        # P2SH should be handled differently, but for now we only implement P2PKH
        z = self.sig_hash(input_index)

        # combine the current ScriptSig and the previous ScriptPubKey
        # This is checked once the transaction has been signed
        combined = tx_in.script_sig + script_pubkey
        # evaluate the combined script
        return combined.evaluate(z)

    def verify(self):
        '''Verify this transaction'''
        # check that we're not creating money
        if self.fee() < 0:
            return False
        # check that each input has a valid ScriptSig
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    # This sets the ScriptSig for spending stuff; it basically provides the correct signature
    # Useful for p2pk and p2pkh
    def sign_input(self, input_index, private_key):
        '''Signs the input using the private key'''
        # get the signature hash (z)
        z = self.sig_hash(input_index)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.point.sec()
        # initialize a new script with [sig, sec] as the cmds
        script_sig = Script([sig, sec])
        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script_sig
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is an integer in 4 bytes, little endian
        prev_index = little_endian_to_int(s.read(4))
        # use Script.parse to get the ScriptSig
        script_sig = Script.parse(s)
        # sequence is an integer in 4 bytes, little-endian
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        '''Get the ScriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # amount is an integer in 8 bytes, little endian
        amount = little_endian_to_int(s.read(8))
        # use Script.parse to get the ScriptPubKey
        script_pubkey = Script.parse(s)
        # return an instance of the class (see __init__ for args)
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result



'''
###########################################
########P2PKH to P2PKH transaction#########
###########################################

#newSecret = hash256(b'ThisIsDumb##JKl45')
#newIntSecret = int(newSecret.hex(),16)
#newPrivKey = PrivateKey(newIntSecret)
#newAddress = newPrivKey.point.address(compressed = True, testnet = True)

# Hard code the new address:
newAddress = 'mgQrZpj8BctqKqBXojUwdnHMaJMLpSYq68'

# First, we need to know which output we will be spending
tx_hash = '867645b1d400f92eea0bb474404dab888b45465baaedd370a30f7afa8845d75a'
tx_index = 4

# value = 68472523

# Defining the input of our transaction (i.e. the output we will be spending)
newInput = TxIn(bytes.fromhex(tx_hash),tx_index)

# To define the output, we need an address
targetAddress = 'mgQrZpj8BctqKqBXojUwdnHMaJMLpSYq68'
# Since it's a p2pkh address we generate the script for this
ScriptPubkey = p2pkh_script_from_address(targetAddress)
# input value = 68472523 output 58472523
newOutput = TxOut(68000000,ScriptPubkey)

# Define a new testnet transaction
newTx = Tx(1,[newInput],[newOutput],0,True)

# We need to sign our input
# For this, we need the private key that controls this output:
secret = hash256(b'IIC3272Sucks')
intSecret = int(secret.hex(),16)
privKey = PrivateKey(intSecret)

input_index = 0
newTx.sign_input(input_index,privKey)

# Check that the transaction parses (fee>=0, sigs OK)
print(newTx.verify())

# Output the serialization:
print(newTx.serialize().hex())

print('Tx hash:',newTx.id())
'''



'''
####################################
########P2PKH to P2SH spend#########
####################################


# First, we need to know which output we will be spending
tx_hash = '230b66e03d9e6ac774ac1e9b93c4833505eca8c9e2cfb547c4d927271d9c1905'
tx_index = 1

# Defining the input of our transaction (i.e. the output we will be spending)
newInput = TxIn(bytes.fromhex(tx_hash),tx_index)

# To define the output, we need an address
targetAddress = '2NGZrVvZG92qGYqzTLjCAewvPZ7JE8S8VxE'
# Since it's a p2pkh address we generate the script for this
ScriptPubkey = p2sh_script_from_address(targetAddress)
# Define the output, leave some transaction fee here output = 1000, txfee = 9000
newOutput = TxOut(1000,ScriptPubkey)

# Define a new testnet transaction
newTx = Tx(1,[newInput],[newOutput],0,True)

# We need to sign our input
# For this, we need the private key that controls this output:
secret = hash256(b'IIC3272Sucks')
intSecret = int(secret.hex(),16)
privKey = PrivateKey(intSecret)

input_index = 0
newTx.sign_input(input_index,privKey)

# Check that the transaction parses (fee>=0, sigs OK)
print(newTx.verify())

# Output the serialization:
print(newTx.serialize().hex())

print(newTx.id())
'''
'''
ttx = 'e9d4f741c9870a635e831b0da38e8c7d432cf52c8c24aa657a19e039c258efa0'
fetcher = TxFetcher()
tx = fetcher.fetch(ttx,testnet=True)

print(tx)

# The following will fail since we have not implemented detecting a coinbase transaction!!!
#print('Output3:',tx.fee())
'''