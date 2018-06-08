#generate fake private and public key for tls client
#generate private and public key for middlebox

from tlslite.constants import GroupName
from tlslite.keyexchange import *
from tlslite.tlsconnection import *
from tlslite.utils.ecc import *
from tlslite.utils.x25519 import *
from tlslite.utils import tlshashlib

def bytearray_to_long(array):
    value = long(0)
    tmp = long(1)
    for i in range(len(array)):
        value = value + array[i] * tmp
        tmp = tmp * 256
    return value

def gen_public_key_from_private_key(curve_name, priv):
    if curve_name == 'x25519' or curve_name == 'secp256r1' or curve_name == 'secp384r1' or curve_name == 'secp521r1':
        if curve_name == 'x25519':
            return x25519(priv, X25519_G)
        else:
            curve = getCurveByName(curve_name)
            # generator is ecdsa.ellipticcurve.Point, private is long
            # encode format: compress format, X, Y
            # decode format: ecdsa.ellipticcurve.Point
            return encodeX962Point(curve.generator * priv)
    else:
        print 'unexpected curve name: ' + curve_name

def gen_fake_private_key_for_client(curve_name, alpha, prev_private_key):
    if curve_name == 'x25519' or curve_name == 'secp256r1' or curve_name == 'secp384r1' or curve_name == 'secp521r1':
        if curve_name == 'x25519':
            # alpha and prev_private_key should be bytearray of length 32
            tmp = x25519(prev_private_key, X25519_G)
            value = x25519(alpha, tmp);
            # now value is g^a[n]^alpha
            # we hash value to 32 bytes as fake random private key
            sha = tlshashlib.sha256()
            sha.update(value)
            return bytearray(sha.digest())
        else:
            # alpha should be long
            # prev_private_key should be ecdsa.ellipticcurve.Point
            curve = getCurveByName(curve_name)
            tmp = curve.generate * prev_private_key
            value = encodeX962Point(tmp * alpha)
            sha = tlshashlib.sha512()
            sha.update(value)
            hashvalue = bytearray(sha.digest())
            return bytearray_to_long(hashvalue) % curve.generator.order()
    else:
        print 'unexpected curve name: ' + curve_name

def gen_private_key_for_middlebox(curve_name, alpha, prev_public_key):
    if 