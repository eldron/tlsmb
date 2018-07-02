class SignatureFragment(object):
    def __init__(self):
        self.type = 0 # of type int
        self.min = 0 # of type int
        self.max = 0 # of type int
        self.s = bytearray() # of type bytearray
        self.hexstring = None # for testing
        self.hit = False # of type bool
        self.rule = None # of type Rule
        self.len = 0 # of type int
        self.offset = 0 # of type int, set during inspection

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}
class DistanceRelation(object):
    RELATION_STAR = 0
    RELATION_EXACT = 1
    RELATION_MAX = 2
    RELATION_MIN = 3
    RELATION_MINMAX = 4

class Rule(object):
    def __init__(self):
        self.rule_name = None # of type str
        self.sfs_count = 0 # of type int, number of signature fragments
        self.signature_fragments_list = [] # list contains SignatureFragment
        self.hit = False # of type bool

def char_to_int(a):
    a = ord(a)
    if ord('0') <= a and a <= ord('9'):
        return a - ord('0')
    elif ord('a') <= a and a <= ord('f'):
        return a - ord('a') + 10
    else:
        return a - ord('A') + 10

def convert_hex_to_int(a, b):
    high = char_to_int(a)
    low = char_to_int(b)
    return (high << 4) | low

def read_rules(filename):
    fin = open(filename, 'r')
    rules = []
    # read the number of rules
    number_of_rules = int(fin.readline())
    for i in range(number_of_rules):
        rule = Rule()
        # read rule name
        rule.rule_name = fin.readline()
        # read the number of signature fragments
        rule.sfs_count = int(fin.readline())
        for j in range(rule.sfs_count):
            # read distance relation type
            signature_fragment = SignatureFragment()
            signature_fragment.type = int(fin.readline())
            if signature_fragment.type == DistanceRelation.RELATION_STAR:
                pass
            elif signature_fragment.type == DistanceRelation.RELATION_MIN:
                signature_fragment.min = int(fin.readline())
            elif signature_fragment.type == DistanceRelation.RELATION_EXACT:
                signature_fragment.min = int(fin.readline())
            elif signature_fragment.type == DistanceRelation.RELATION_MAX:
                signature_fragment.max = int(fin.readline())
            else:
                signature_fragment.min = int(fin.readline())
                signature_fragment.max = int(fin.readline())

            signature_fragment.rule = rule
            # read hex string, convert to 
            hexstring = fin.readline()
            signature_fragment.hexstring = hexstring
            signature_fragment.len = (len(hexstring) - 1) / 2
            for k in range(signature_fragment.len):
                signature_fragment.s.append(convert_hex_to_int(hexstring[2 * k], hexstring[2 * k + 1]))
            rule.signature_fragments_list.append(signature_fragment)
        
        rules.append(rule)

    fin.close()
    return rules

def print_sf(sf):
    print sf.type
    print sf.min
    print sf.max
    print sf.hexstring

def print_rule(rule):
    print rule.rule_name
    print rule.sfs_count
    for sf in rule.signature_fragments_list:
        print_sf(sf)

def print_rules(rules):
    print 'number of rules is:'
    print len(rules)
    for rule in rules:
        print_rule(rule)

if __name__ == '__main__':
    rules = read_rules('rules_2000')
    print_rules(rules)