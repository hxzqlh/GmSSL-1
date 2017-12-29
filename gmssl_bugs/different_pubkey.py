# BUG2
# public key from libsm2.generate_key is different with public key from libsm2.getPKFromSK, possibility occur, loop 10000 times

# OUTPUT
# print the different public key pair

import libsm2
import time

ctx = libsm2.Context()

message = "0456789458752102"
hash = libsm2.hash(message.decode('hex'))
print (message.decode('hex').encode('hex'))

for i in range(10000):
    keypair = libsm2.generate_key(ctx)
    pk = keypair[0]
    sk = keypair[1]
    pk_from_sk = libsm2.getPKFromSK(ctx, sk)
    sign = libsm2.sign(ctx, sk, hash)
    pk_recover = libsm2.recover(ctx, hash, sign)
    # test generated pk and pk from sk
    if pk.encode('hex') != pk_from_sk.encode('hex'):
        print (i)
        print ("pk: ", pk.encode('hex'))
        print ("pk from sk: ", pk_from_sk.encode('hex'))
