from collections import deque

class SnortContent(object):
    def __init__(self):
        self.content = None # of type bytearray
        self.distance = 0 # of type int
        self.within = 0 # of type int
        self.has_distance = False
        self.has_within = False
        self.pcre = None # of type bytearray, not used for now
        self.rule = None # of type SnortRule
        self.hit = False
        self.offset = 0 # of type int, set during inspection

    def print_content(self):
        print 'content is: '
        print self.content
        if self.has_distance:
            print 'distance is:'
            print self.distance
        if self.has_within:
            print 'within is:'
            print self.within

class SnortRule(object):
    def __init__(self):
        self.contents_list = []
        self.sid = 0 # of type int
        self.gid = 0 # of type int
        self.hit = False # set during inspection
    
    def check_rule(self):
        content_list_len = len(self.contents_list)
        if self.contents_list[0].hit == False:
            return False

        i = 1
        while i < content_list_len:
            next_c = self.contents_list[i]
            prev_c = self.contents_list[i - 1]
            if next_c.hit and prev_c.hit:
                if next_c.has_distance:
                    if next_c.offset < prev_c.offset + next_c.distance + len(next_c.content):
                        return False
                if next_c.has_within:
                    if next_c.offset > prev_c.offset + next_c.within + len(next_c.content):
                        return False
            else:
                return False
            i = i + 1
        return True

    def print_rule(self):
        print 'sid is:'
        print self.sid
        for content in self.contents_list:
            content.print_content()

def cal_content(s):
    content = bytearray()
    hex_begin = False
    i = 0
    while i < len(s):
        if s[i] == '|':
            if hex_begin:
                hex_begin = False
            else:
                hex_begin = True
            i = i + 1
        else:
            if hex_begin:
                if s[i] == ' ':
                    i = i + 1
                else:
                    # convert 2 bytes to hex value
                    content.append(convert_hex_to_int(s[i], s[i + 1]))
                    i = i + 2
            else:
                # convert the current to hex value
                content.append(ord(s[i]))
                i = i + 1
    return content

def read_snort_rules(filename):
    fin = open(filename, 'r')
    lines = fin.readlines()
    fin.close()
    rules = []
    for line in lines:
        if 'content:"' in line:
            print 'processing ' + line
            rule = SnortRule()
            rules.append(rule)
            splits = line.split(';')
            for sp in splits:
                if ' sid:' in sp:
                    idx = sp.find(':')
                    rule.sid = int(sp[idx + 1:])

                if 'content:"' in sp:
                    snort_content = SnortContent()
                    substrings = sp.split(',')
                    for s in substrings:
                        if 'content:"' in s:
                            # we set content here
                            begin_idx = s.find('"') + 1
                            end_idx = s.find('"', begin_idx)
                            snort_content.content = cal_content(s[begin_idx: end_idx])
                        elif 'distance' in s:
                            # we set distance here
                            idx = s.find(' ')
                            snort_content.has_distance = True
                            try:
                                snort_content.distance = int(s[idx + 1:])
                            except ValueError:
                                snort_content.has_distance = False
                        elif 'within' in s:
                            # we set within here
                            idx = s.find(' ')
                            snort_content.has_within = True
                            try:
                                snort_content.within = int(s[idx + 1:])
                            except ValueError:
                                snort_content.has_within = False

                    rule.contents_list.append(snort_content)

    return rules


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

class RuleType(object):
    CLAMAV = 0
    SNORT = 1
    BRO = 3

class Rule(object):
    def __init__(self):
        self.rule_name = None # of type str
        self.sfs_count = 0 # of type int, number of signature fragments
        self.sfs = [] # list contains SignatureFragment
        self.hit = False # of type bool

    def check_rule(self):
        return check_rule(self)

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

def build_ac_graph(rules, rule_type):
    state_count = 0
    current_state = 0
    states = []
    zero_state = State()
    states.append(zero_state)

    for rule in rules:
        if rule_type == RuleType.CLAMAV:
            sf_or_content_count = rule.sfs_count
        else:
            sf_or_content_count = len(rule.contents_list)
        for j in range(sf_or_content_count):
            #sf = rule.sfs[j]
            if rule_type == RuleType.CLAMAV:
                sf = rule.sfs[j]
            else:
                sf = rule.contents_list[j]
            
            current_state = 0
            k = 0
            
            if rule_type == RuleType.CLAMAV:
                content_len = len(sf.s)
            else:
                content_len = len(sf.content)

            while k < content_len:
                if rule_type == RuleType.CLAMAV:
                    next_state = transit(states, current_state, sf.s[k])
                else:
                    next_state = transit(states, current_state, sf.content[k])
                if next_state == -1:
                    # did not find edge for the current token, need to add edges for the following tokens
                    break
                else:
                    k = k + 1
                    current_state = next_state

            if k == content_len:
                # the signature fragment already exists
                # we add the the current signature fragment to the state's output list
                states[current_state].output.append(sf)
            else:
                # add edges for the following tokens
                while k < content_len:
                    edge = Edge()
                    if rule_type == RuleType.CLAMAV:
                        edge.token = sf.s[k]
                    else:
                        edge.token = sf.content[k]

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
            if len(states[edge.state_number].output) > 0:
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
        self.rule_type = RuleType.CLAMAV

    # called in a loop to perform inspection
    def inspect(self, data):
        for token in data:
            value = ac_inspect(self.states, self.global_state_number, token, self.offset, self.matched_rules)
            self.global_state_number = value
            self.offset = self.offset + 1
        
    def clear_after_inspection(self):
        for rule in self.rules:
            rule.hit = False
            if self.rule_type == RuleType.CLAMAV:
                for sf in rule.sfs:
                    sf.hit = False
                    sf.offset = 0
            elif self.rule_type == RuleType.SNORT:
                for c in rule.contents_list:
                    c.hit = False
                    c.offset = 0

    def initialize_ac_inspect(self, filename, rule_type):
        self.rules = read_rules(filename)
        self.rule_type = rule_type
        self.states = build_ac_graph(self.rules, rule_type)
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
    ac_inspect = ACInspect()
    ac_inspect.initialize_ac_inspect('rules_2000', RuleType.CLAMAV)
    fin = open('rules_2000', 'r')
    lines = fin.readlines()
    fin.close()
    for line in lines:
        ac_inspect.inspect(bytearray(line))

    print_rules(ac_inspect.matched_rules)