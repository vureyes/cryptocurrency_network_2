# As usual, most of the code is stolen from Jimmy Song's book, I just made it worse

from io import BytesIO

from base58 import *

from op import *

from ecc import *


class Script:

    # The basic constructor; either empty list of commands, or some commands
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    # This is just for printing the script for debugging purposes
    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    # We'll want to concatenate two scripts (scriptSig + scriptPubKey)
    # For this we overload the sum operator (+)
    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    # If we get a script in bytes, we want to decode the actual commands it has
    # This method does so, and returns an object of the class Script (hence @classmethod)
    @classmethod
    def parse(cls, s):
        # get the length of the entire field
        length = read_varint(s)
        # initialize the cmds array
        cmds = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                # we have an cmd set n to be the current byte
                n = current_byte
                # add the next n bytes as an cmd
                cmds.append(s.read(n))
                # increase the count by n
                count += n
            # I'm omitting two cases that are currently supported in Bitcoin
            # We'll examine OP_PUSHDATA1 and OP_PUSHDATA2 only in theory :-)
            # I'll provide a more complete code later on
            else:
                # we have an opcode. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of cmds
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    # This is the opposite of parse: we have an object of class Script, and we need to return bytes
    # Serializes the object of our class to a format accepted by the network
    def raw_serialize(self):
        # initialize what we'll send back
        result = b''
        # go through each cmd
        for cmd in self.cmds:
            # if the cmd is an integer, it's an opcode
            if type(cmd) == int:
                # turn the cmd into a single byte integer using int_to_little_endian
                result += int_to_little_endian(cmd, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(cmd)
                # We'll assume at most 75 bytes of data
                if length >= 75:
                    raise ValueError('too long an cmd')
                    # Technically we should support up to 520 bytes; same as with OP_PUSHDATA1/2
                result += int_to_little_endian(length, 1)
                result += cmd
        return result

    # This just completes the job and wraps everything as needed
    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    # How do we check that the script is OK?
    # We need to evaluate it
    # Any checksig operation will have to verify a signature of the (hash of the) corresponding transaction
    # For this, we will pass this hash, z, as a parameter to the evaluation method
    def evaluate(self, z):
        # create a copy as we may need to add to this list if we have a RedeemScript
        cmds = self.cmds[:]
        stack = []
        # Technically, Script has an acces to a second stack via a few commands, but we will not use that here
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                # The command is an pocode, so do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]

                # The commands that will need the z for checking sig are OP_CHECKSIG and OP_CHECKSIGVERIFY
                # Their codes are 172 and 173
                # On https://en.bitcoin.it/wiki/Script you can also check that 174 and 175 also need z
                if cmd in (172, 173):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        return False
                else:
                    if not operation(stack):
                        return False
            else:
                # cmd is data, so add the cmd to the stack
                stack.append(cmd)

        # If we end up with an empty stack the execution failed
        if len(stack) == 0:
            return False
        # If we end up with False on the stack, the execution also failed
        # Need to tell you about numbers a bit more
        if stack.pop() == b'':
            return False
        return True


# A shortcut for creating a P2PKH script from the hash160 that appears in the script
def p2pkh_script(h160):
    '''Takes a hash160 and returns the p2pkh ScriptPubKey'''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])

# A shortcut for creating a P2PKH script from the p2pkh address
def p2pkh_script_from_address(address):
    '''Takes a p2pkh address and returns the p2pkh ScriptPubKey for this address'''

    # The address format is what you would see on the network; e.g n3jKhCmVjvaVgg8C5P7E48fdRkQAAvf7Wc
    # THIS IS NOT IN BYTES!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    # Check the prefix: https://en.bitcoin.it/wiki/List_of_address_prefixes
    if not ((address[0] == '1') or (address[0] == 'm') or (address[0] == 'n')):
        raise ValueError('not a valid p2pkh address')

    h160 = decode_base58(address)

    return Script([0x76, 0xa9, h160, 0x88, 0xac])


# A shortcut for creating a P2SH script from the hash160 that appears in the script
def p2sh_script(h160):
    '''Takes a hash160 and returns the p2sh ScriptPubKey'''
    return Script([0xa9, h160, 0x87])


# A shortcut for creating a P2SH script from the p2sh address that appears in the script
def p2sh_script_from_address(address):
    '''Takes a hash160 and returns the p2sh ScriptPubKey'''

    # The address format is what you would see on the network; e.g 3P14159f73E4gFr7JterCCQh9QjiTjiZrG

    # Check the prefix: https://en.bitcoin.it/wiki/List_of_address_prefixes
    if not ((address[0] == '3') or (address[0] == '2')):
        raise ValueError('not a valid p2sh address')

    h160 = decode_base58(address)

    return Script([0xa9, h160, 0x87])


##############################
###########TESTING############
##############################


'''
tmp = hash160(b'Hola')

### Script is: data data OP_EQUAL
script = Script([tmp, tmp, 0x87])

print(script.evaluate(tmp))


### Script is: data data OP_EQUALVERIFY
script = Script([tmp, tmp, 0x88])

print(script.evaluate(tmp))


##################################

z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')

script = Script([sig, sec, 0xac])

print(script.evaluate(z))



###################################

# Generating my private key:
secret = hash256(b'IIC3272Sucks')
intSecret = int(secret.hex(),16)

privKey = PrivateKey(intSecret)

# Signing a message:
message = hash256(b'This course is boring!')
z = int(message.hex(),16)

signature = privKey.sign(z)

# Get the public key in SEC format
secPubKey = privKey.point.sec()

# Get the signature in DER format
derSig = signature.der()

# Need to append the SIGHASH_ALL field to verify the entire transaction!!!!!!!!!
derSig = derSig + SIGHASH_ALL.to_bytes(1,'big')

script = Script([derSig, secPubKey, 0xac])
print(script.evaluate(z))

###################################
'''
'''
########################
#########P2PKH##########
########################

# Generating my private key:
secret = hash256(b'IIC3272Sucks')
intSecret = int(secret.hex(),16)

privKey = PrivateKey(intSecret)

# Signing a message:
message = hash256(b'This course is boring!')
z = int(message.hex(),16)

signature = privKey.sign(z)

# Get the public key in SEC format
secPubKey = privKey.point.sec()

# Get the signature in DER format
derSig = signature.der()

# Need to append the SIGHASH_ALL field to verify the entire transaction!!!!!!!!!
derSig = derSig + SIGHASH_ALL.to_bytes(1,'big')

h160 = hash160(secPubKey)

script = Script([derSig, secPubKey, 0x76, 0xa9, h160, 0x88, 0xac])
print(script.evaluate(z))
'''
'''
# Generating my private key:
secret = hash256(b'IIC3272Sucks')
intSecret = int(secret.hex(),16)

privKey = PrivateKey(intSecret)

# Signing a message:
message = hash256(b'This course is boring!')
z = int(message.hex(),16)

signature = privKey.sign(z)

# Get the public key in SEC format
secPubKey = privKey.point.sec()

# Get the signature in DER format
derSig = signature.der()

# Need to append the SIGHASH_ALL field to verify the entire transaction!!!!!!!!!
derSig = derSig + SIGHASH_ALL.to_bytes(1,'big')

h160 = hash160(secPubKey)

print(h160)
print(h160.hex())

script = Script([0x76, 0xa9, h160, 0x88, 0xac])
print(script)
'''


'''
##################################################
# Generating a p2pkh script from a p2pkh address #
##################################################
address = 'n3jKhCmVjvaVgg8C5P7E48fdRkQAAvf7Wc'
print('The script:',p2pkh_script_from_address(address))
print('The script serialized in hex:',p2pkh_script_from_address(address).serialize().hex())


h160 = decode_base58(address)
print(h160_to_p2pkh_address(h160,testnet=True))

address = '2NGZrVvZG92qGYqzTLjCAewvPZ7JE8S8VxE'
print('The script:',p2sh_script_from_address(address))
print('The script serialized in hex:',p2sh_script_from_address(address).serialize().hex())

h160 = decode_base58(address)
print(h160_to_p2sh_address(h160,testnet=True))

'''