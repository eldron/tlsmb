from tlslite.constants import GroupName
from tlslite.tlsconnection import *
from tlslite.keyexchange import *
import binascii

group_id = getattr(GroupName, 'x25519')
kex = ECDHKeyExchange(group_id, (3, 4))
priv = kex.get_random_private_key()
share = kex.calc_public_value(priv)
print binascii.hexlify(priv)
print binascii.hexlify(share)