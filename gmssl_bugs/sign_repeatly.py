# BUG1
# we get different result when sign one message repeatly with same private key

# OUTPUT
# the sign and sign_again will be different 

import libsm2

ctx = libsm2.Context()

keypair = libsm2.generate_key(ctx)

message = "45678945875212"
print ("message: ", message)

hash = libsm2.hash(message.decode('hex'))
print ("hash: ", hash.encode('hex'))

sk = keypair[1]
print ("sk: ", sk.encode('hex'))
print ("pk: ", keypair[0].encode('hex'))
pk = libsm2.getPKFromSK(ctx, sk)
print ("pk from sk: ", pk.encode('hex'))

sign = libsm2.sign(ctx, sk, hash)
print ("sign: ", sign.encode('hex'))

sign_again = libsm2.sign(ctx, sk, hash)
print ("sign_again: ", sign_again.encode('hex'))
