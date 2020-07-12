from io import BytesIO

from helper import (
    bits_to_target,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_root,
)

from txP2PKH import *


GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
TESTNET_GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
LOWEST_BITS = bytes.fromhex('ffff001d')


class Block:

    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a block. Returns a Block object'''
        # s.read(n) will read n bytes from the stream
        # version - 4 bytes, little endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian, interpret as int
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        '''Returns the 80 byte block header'''
        # version - 4 bytes, little endian
        result = int_to_little_endian(self.version, 4)
        # prev_block - 32 bytes, little endian
        result += self.prev_block[::-1]
        # merkle_root - 32 bytes, little endian
        result += self.merkle_root[::-1]
        # timestamp - 4 bytes, little endian
        result += int_to_little_endian(self.timestamp, 4)
        # bits - 4 bytes
        result += self.bits
        # nonce - 4 bytes
        result += self.nonce
        return result

    def hash(self):
        '''Returns the hash256 interpreted little endian of the block'''
        # serialize
        s = self.serialize()
        # hash256
        h256 = hash256(s)
        # reverse
        return h256[::-1]


    def target(self):
        '''Returns the proof-of-work target based on the bits'''
        return bits_to_target(self.bits)

    def difficulty(self):
        '''Returns the block difficulty based on the bits'''
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest = 0xffff * 256**(0x1d - 3)
        return lowest / self.target()

    def check_pow(self):
        '''Returns whether this block satisfies proof of work'''
        # get the hash256 of the serialization of this block
        h256 = hash256(self.serialize())
        # interpret this hash as a little-endian number
        proof = little_endian_to_int(h256)
        # return whether this integer is less than the target
        return proof < self.target()



'''
Full block class guards the entire block, with the transactions inside
IMPLEMENT FOR HOMEWORK
'''
class FullBlock:

    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, nr_trans=0, txs=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        # This is the number of txs as varint
        self.nr_trans = nr_trans
        # These are the transactions themselves (object of class Tx), an array of size nr_trans
        self.txs = txs

    def __repr__(self):
        return 'block: \nversion: {}\nprev_block:{}\nmerkle_root:{}\ntimestamp: {}\nbits: {}\nnonce: {}\nnr_trans: {}\n'.format(
            self.version,
            self.prev_block.hex(),
            self.merkle_root.hex(),
            self.timestamp,
            self.bits.hex(),
            self.nonce.hex(),
            self.nr_trans
        )

    @classmethod
    def parse(cls, s):
        #FIGURE IT OUT
        return 1

    def serialize(self):
        #FIGURE IT OUT
        # MAKE SURE YOU KNOW WHAT NEEDS TO BE HASHED
        result = b''
        return result

    def hash(self):
        '''Returns the hash256 interpreted little endian of the block'''
        # serialize
        s = self.serialize()
        # hash256
        h256 = hash256(s)
        # reverse
        return h256[::-1]

    def target(self):
        '''Returns the proof-of-work target based on the bits'''
        return bits_to_target(self.bits)

    def difficulty(self):
        '''Returns the block difficulty based on the bits'''
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest = 0xffff * 256**(0x1d - 3)
        return lowest / self.target()

    def check_pow(self):
        '''Returns whether this block satisfies proof of work'''
        # get the hash256 of the serialization of this block
        h256 = hash256(self.serialize())
        # interpret this hash as a little-endian number
        proof = little_endian_to_int(h256)
        # return whether this integer is less than the target
        return proof < self.target()

