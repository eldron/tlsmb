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
            # priv is of type bytearray
            # generator is of type bytearray
            return x25519(priv, X25519_G)
        else:
            curve = getCurveByName(curve_name)
            # generator is ecdsa.ellipticcurve.Point, priv is long
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
            tmp = curve.generator * prev_private_key
            value = encodeX962Point(tmp * alpha)
            sha = tlshashlib.sha256()
            sha.update(value)
            hashvalue = bytearray(sha.digest())
            return bytearray_to_long(hashvalue) % curve.generator.order()
    else:
        print 'unexpected curve name: ' + curve_name

def gen_private_key_for_middlebox(curve_name, alpha, prev_public_key):
    if curve_name == 'x25519':
        # alpha and prev_public_key should be bytearray of length 32
        value = x25519(alpha, prev_public_key)
        sha = tlshashlib.sha256()
        sha.update(value)
        return bytearray(sha.digest())
    elif curve_name == 'secp256r1' or curve_name == 'secp384r1' or curve_name == 'secp521r1':
        # alpha should be of type long
        # prev_public_key should be of type ecdsa.ellipticcurve.Point
        curve = getCurveByName(curve_name)
        value = encodeX962Point(prev_public_key * alpha)
        sha = tlshashlib.sha256()
        sha.update(value)
        hashvalue = bytearray(sha.digest())
        return bytearray_to_long(hashvalue) % curve.generator.order()
    else:
        print 'unexpected curve name: ' + curve_name

# test secp curves
def test_key_gen(curve_name):
    curve = getCurveByName(curve_name)
    if curve_name == 'secp256r1':
        group = ECDHKeyExchange(GroupName.secp256r1, (3, 4))
    elif curve_name == 'secp384r1':
        group = ECDHKeyExchange(GroupName.secp384r1, (3, 4))
    else:
        group = ECDHKeyExchange(GroupName.secp521r1, (3, 4))

    private_key = group.get_random_private_key()
    alpha = group.get_random_private_key()
    #public_key = curve.generator * private_key
    public_key = group.calc_public_value(private_key)
    client_private_key = gen_fake_private_key_for_client(curve_name, alpha, private_key)
    middlebox_private_key = gen_private_key_for_middlebox(curve_name, alpha, decodeX962Point(public_key, curve))
    if client_private_key == middlebox_private_key:
        print 'test ' + curve_name + ' succeeded'
    else:
        print 'test ' + curve_name + ' failed'

if __name__ == '__main__':
    group = ECDHKeyExchange(GroupName.x25519, (3, 4))
    private_key = group.get_random_private_key()
    public_key = group.calc_public_value(private_key)
    alpha = group.get_random_private_key()
    # create private key for client
    client_private_key = gen_fake_private_key_for_client('x25519', alpha, private_key)
    # create private key for middlebox
    middlebox_private_key = gen_private_key_for_middlebox('x25519', alpha, public_key)
    if client_private_key == middlebox_private_key:
        print 'x25519: client_private_key equals middlebox_private_key'
    else:
        print 'x25519: client private key does not equal to middlebox private key'

    test_key_gen('secp256r1')
    test_key_gen('secp384r1')
    test_key_gen('secp521r1')