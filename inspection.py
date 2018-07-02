from collections import deque

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
        self.sfs = [] # list contains SignatureFragment
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
            rule.sfs.append(signature_fragment)
        
        rules.append(rule)

    fin.close()
    return rules

class Edge(object):
    def __init__(self):
        self.token = 0 # of type int, 0-255
        self.state_number = 0 # of type int

class State(object):
    def __init__(self):
        self.state_number = 0 # of type int
        self.fail_state_number = 0 # of type int
        self.edges = [] # contains edges
        self.output = [] # contains signature fragments

# used to build the ac graph
def transit(states, state_number, token):
    for edge in states[state_number].edges:
        if edge.token == token:
            return edge.state_number
    return -1

def build_ac_graph(rules):
    state_count = 0
    current_state = 0
    states = []
    zero_state = State()
    states.append(zero_state)

    for i in range(len(rules)):
        rule = rules[i]
        for j in range(rule.sfs_count):
            sf = rule.sfs[j]
            current_state = 0
            k = 0
            while k < len(sf.s):
                next_state = transit(states, current_state, sf.s[k])
                if next_state == -1:
                    # did not find edge for the current token, need to add edges for the following tokens
                    break
                else:
                    k = k + 1
                    current_state = next_state

            if k == len(sf.s):
                # the signature fragment already exists
                # we add the the current signature fragment to the state's output list
                states[current_state].output.append(sf)
            else:
                # add edges for the following tokens
                while k < len(sf.s):
                    edge = Edge()
                    edge.token = sf.s[k]
                    edge.state_number = state_count + 1
                    states[current_state].edges.append(edge)
                    newstate = State()
                    newstate.state_number = state_count + 1
                    states.append(newstate)
                    state_count = state_count + 1
                    current_state = state_count
                    k = k + 1
    return states

def zero_goto_func(states, token):
    for edge in states[0].edges:
        if edge.token == token:
            return edge.state_number
    return 0

def goto_func(states, state_number, token):
    if state_number == 0:
        return zero_goto_func(states, token)
    else:
        return transit(states, state_number, token)

def cal_failure_state(states):
    queue = deque()
    for edge in states[0].edges:
        states[edge.state_number].fail_state_number = 0
        queue.append(states[edge.state_number])

    while len(queue) > 0:
        current = queue.popleft()
        for edge in current.edges:
            queue.append(states[edge.state_number])
            fail_state = current.fail_state_number
            while True:
                if goto_func(states, fail_state, edge.token) == -1:
                    fail_state = states[fail_state].fail_state_number
                else:
                    break
            states[edge.state_number].fail_state_number = goto_func(states, fail_state, edge.token)

            # modify the output list
            if len(states[edge.state_number].output > 0):
                tmp = states[edge.state_number].fail_state_number
                tmp = states[tmp]
                for sf in tmp.output:
                    states[edge.state_number].output.append(sf)

def check_rule(r):
    for sf in r.sfs:
        if sf.hit == False:
            return False

	# check distance relationship between the signature fragments
    i = 1
    while i < r.sfs_count:
        if r.sfs[i].type == DistanceRelation.RELATION_STAR:
            pass
        elif r.sfs[i].type == DistanceRelation.RELATION_EXACT:
            if r.sfs[i - 1].offset + r.sfs[i - 1].len + r.sfs[i].min == r.sfs[i].offset:
                pass
            else:
                return False
        elif r.sfs[i].type == DistanceRelation.RELATION_MIN:
            if r.sfs[i - 1].offset + r.sfs[i - 1].len + r.sfs[i].min <= r.sfs[i].offset:
                pass
            else:
                return False
        elif r.sfs[i].type == DistanceRelation.RELATION_MAX:
            if r.sfs[i - 1].offset + r.sfs[i - 1].len + r.sfs[i].max >= r.sfs[i].offset:
                pass
            else:
                return False
        else:
            if r.sfs[i - 1].offset + r.sfs[i - 1].len + r.sfs[i].min <= r.sfs[i].offset and r.sfs[i - 1].offset + r.sfs[i - 1].len + r.sfs[i].max >= r.sfs[i].offset:
                pass
            else:
                return False
        i = i + 1

	return True

def ac_inspect(states, global_state_number, token, offset, matched_rules):
    while goto_func(states, global_state_number, token) == -1:
        global_state_number = states[global_state_number].fail_state_number
    global_state_number = goto_func(states, global_state_number, token)

    if len(states[global_state_number].output) > 0:
        # check if the corresponding rules are matched
        for sf in states[global_state_number].output:
            sf.hit = True
            sf.offset = offset
            if check_rule(sf.rule):
                if sf.rule.hit:
                    pass
                else:
                    sf.rule.hit = True
                    matched_rules.append(sf.rule)
        global_state_number = 0
    return global_state_number

class ACInspect(object):
    def __init__(self):
        self.states = None
        self.rules = []
        self.global_state_number = 0
        self.matched_rules = []
        self.offset = 0

    def inspect(self, data):
        for token in data:
            self.global_state_number = ac_inspect(self.states, self.global_state_number, token, self.offset, self.matched_rules)
            self.offset = self.offset + 1
        
    def clear_after_inspection(self):
        for rule in self.rules:
            rule.hit = False
            for sf in rule.sfs:
                sf.hit = False
                sf.offset = 0

    def initialize_ac_inspect(self, filename):
        self.rules = read_rules(filename)
        self.states = build_ac_graph(self.rules)
        cal_failure_state(self.states)
        
def print_sf(sf):
    print sf.type
    print sf.min
    print sf.max
    print sf.hexstring

def print_rule(rule):
    print rule.rule_name
    print rule.sfs_count
    for sf in rule.sfs:
        print_sf(sf)

def print_rules(rules):
    print 'number of rules is:'
    print len(rules)
    for rule in rules:
        print_rule(rule)

if __name__ == '__main__':
    rules = read_rules('rules_2000')
    print_rules(rules)