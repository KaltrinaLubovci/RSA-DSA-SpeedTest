# coding=utf-8
import Crypto.Hash.SHA256 as SHA256
import Crypto.Signature.PKCS1_v1_5 as PKCS1_v1_5
import Crypto.PublicKey.DSA as DSA
import Crypto.Util.number as CUN
import os
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Create a new DSA key
key = DSA.generate(2048)
f = open("public_key.pem", "w")
f.write(key.publickey().export_key(key))

# Sign a message
message = "Hello"
hash_obj = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = key.sign(hash_obj)

# Load the public key
f = open("public_key.pem", "r")
hash_obj = SHA256.new(message)
pub_key = DSA.import_key(f.read())

# Verify the authenticity of the message
if pub_key.verify(hash_obj, signature):
    print "OK"
else:
    print "Incorrect signature"

