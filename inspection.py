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

# s should be of type str
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
                    content.append(Util.convert_hex_to_int(s[i], s[i + 1]))
                    i = i + 2
            else:
                # convert the current to hex value
                content.append(ord(s[i]))
                i = i + 1
    return content

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
class Util(object):
    @staticmethod
    def char_to_int(a):
        a = ord(a)
        if ord('0') <= a and a <= ord('9'):
            return a - ord('0')
        elif ord('a') <= a and a <= ord('f'):
            return a - ord('a') + 10
        else:
            return a - ord('A') + 10

    @staticmethod
    def convert_hex_to_int(a, b):
        high = Util.char_to_int(a)
        low = Util.char_to_int(b)
        return (high << 4) | low

class Edge(object):
    def __init__(self):
        self.token = -2 # of type int, 0-255
        self.state_number = -2 # of type int

    def print_edge(self):
        print 'token:'
        print chr(self.token)
        print 'state_number:'
        print self.state_number

class State(object):
    def __init__(self):
        self.state_number = 0 # of type int
        self.fail_state_number = 0 # of type int
        self.edges = [] # contains edges
        for i in range(256):
            edge = Edge()
            edge.token = i
            self.edges.append(edge)

        self.output = [] # contains signature fragments

    def print_state(self):
        print 'state number:'
        print self.state_number
        print 'fail state number:'
        print self.fail_state_number
        print 'number of edges:'
        print len(self.edges)
        for edge in self.edges:
            edge.print_edge()
        print 'output:'
        for o in self.output:
            print o
        print '\n'

# used to build the ac graph
def transit(states, state_number, token):
    next_state = states[state_number].edges[token].state_number
    if next_state == -2:
        return -1
    else:
        return next_state

def enter_pattern(states, pattern, rule_type):
    if rule_type == RuleType.CLAMAV:
        s = pattern.s
    elif rule_type == RuleType.SNORT:
        s = pattern.content
    else:
        s = pattern

    current_state = 0
    j = 0
    while j < len(s):
        next_state = transit(states, current_state, s[j])
        if next_state == -1:
            # did not find edge for the current pattern, add edges
            break
        else:
            j = j + 1
            current_state = next_state
    if j == len(s):
        # add to the output list
        states[current_state].output.append(pattern)
    else:
        # add edges for the following tokens
        while j < len(s):
            # edge = Edge()
            # edge.token = s[j]
            # edge.state_number = len(states)
            # states[current_state].edges.append(edge)
            states[current_state].edges[s[j]].state_number = len(states)
            current_state = len(states)
            newstate = State()
            newstate.state_number = current_state
            states.append(newstate)
            j = j + 1
        # add to the output list
        states[current_state].output.append(pattern)

def build_ac_graph_from_patterns(patterns):
    states = []
    states.append(State())
    for pattern in patterns:
        enter_pattern(states, pattern, 3)
    return states

def build_ac_graph(rules, rule_type):
    states = []
    zero_state = State()
    states.append(zero_state)

    if rule_type == RuleType.CLAMAV:
        for rule in rules:
            for pattern in rule.sfs:
                enter_pattern(states, pattern, rule_type)
            print rule.rule_name + 'processed'
    else:
        for rule in rules:
            for pattern in rule.contents_list:
                enter_pattern(states, pattern, rule_type)
    return states

# token should be int of range [0, 255]
def zero_goto_func(states, token):
    next_state = states[0].edges[token].state_number
    if next_state == -2:
        return 0
    else:
        return next_state

def goto_func(states, state_number, token):
    if state_number == 0:
        return zero_goto_func(states, token)
    else:
        return transit(states, state_number, token)

def print_states(states):
    print 'number of states:'
    print len(states)
    for state in states:
        state.print_state()

def cal_failure_state(states):
    queue = deque()
    for edge in states[0].edges:
        if edge.state_number == -2:
            pass
        else:
            states[edge.state_number].fail_state_number = 0
            queue.append(states[edge.state_number])

    while len(queue) > 0:
        current = queue.popleft()
        for edge in current.edges:
            if edge.state_number == -2:
                pass
            else:
                queue.append(states[edge.state_number])
                fail_state = current.fail_state_number
                while True:
                    if goto_func(states, fail_state, edge.token) == -1:
                        fail_state = states[fail_state].fail_state_number
                    else:
                        break
                states[edge.state_number].fail_state_number = goto_func(states, fail_state, edge.token)

                #modify the output list
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
            if r.sfs[i - 1].offset + r.sfs[i].len + r.sfs[i].min == r.sfs[i].offset:
                pass
            else:
                return False
        elif r.sfs[i].type == DistanceRelation.RELATION_MIN:
            if r.sfs[i - 1].offset + r.sfs[i].len + r.sfs[i].min <= r.sfs[i].offset:
                pass
            else:
                return False
        elif r.sfs[i].type == DistanceRelation.RELATION_MAX:
            if r.sfs[i - 1].offset + r.sfs[i].len + r.sfs[i].max >= r.sfs[i].offset:
                pass
            else:
                return False
        else:
            if r.sfs[i - 1].offset + r.sfs[i].len + r.sfs[i].min <= r.sfs[i].offset and r.sfs[i - 1].offset + r.sfs[i].len + r.sfs[i].max >= r.sfs[i].offset:
                pass
            else:
                return False
        i = i + 1

	return True

def ac_inspect_string(states, s):
    state_number = 0
    matched_patterns = []
    for token in s:
        while goto_func(states, state_number, token) == -1:
            state_number = states[state_number].fail_state_number
        state_number = goto_func(states, state_number, token)
        if len(states[state_number].output) > 0:
            for pattern in states[state_number].output:
                matched_patterns.append(pattern)
    
    return matched_patterns

class ACInspect(object):
    def __init__(self):
        self.states = None
        self.rules = []
        self.global_state_number = 0
        self.matched_rules = []
        self.offset = 0
        self.rule_type = RuleType.CLAMAV

    def ac_inspect(self, states, global_state_number, token, offset, matched_rules):
        print 'ac_inspect: offset = ' + str(offset)

        while goto_func(states, global_state_number, token) == -1:
            global_state_number = states[global_state_number].fail_state_number
        global_state_number = goto_func(states, global_state_number, token)

        if len(states[global_state_number].output) > 0:
            # check if the corresponding rules are matched
            for sf in states[global_state_number].output:
                sf.hit = True
                sf.offset = offset
                if sf.rule.check_rule():
                    if sf.rule.hit:
                        pass
                    else:
                        sf.rule.hit = True
                        matched_rules.append(sf.rule)
            global_state_number = 0
        return global_state_number
        
    # called in a loop to perform inspection
    def inspect(self, data):
        for token in data:
            value = self.ac_inspect(self.states, self.global_state_number, token, self.offset, self.matched_rules)
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
        if rule_type == RuleType.CLAMAV:
            self.rules = self.read_clamav_rules(filename)
            print 'read clamav rules'
        elif rule_type == RuleType.SNORT:
            self.rules = self.read_snort_rules(filename)
            print 'read snort rules'
        else:
            print 'unsupported rule type'
            return
        
        self.rule_type = rule_type
        self.states = build_ac_graph(self.rules, rule_type)
        cal_failure_state(self.states)
    
    def read_snort_rules(self, filename):
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
                        snort_content.rule = rule
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

    def read_clamav_rules(self, filename):
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
                    signature_fragment.s.append(Util.convert_hex_to_int(hexstring[2 * k], hexstring[2 * k + 1]))
                rule.sfs.append(signature_fragment)
            
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
    for sf in rule.sfs:
        print_sf(sf)

def print_rules(rules):
    print 'number of rules is:'
    print len(rules)
    for rule in rules:
        print_rule(rule)

if __name__ == '__main__':
    # patterns = []
    # patterns.append(bytearray('he'))
    # patterns.append(bytearray('she'))
    # patterns.append(bytearray('his'))
    # patterns.append(bytearray('hers'))
    # states = build_ac_graph_from_patterns(patterns)
    # print 'built ac graph'
    # cal_failure_state(states)
    # print 'calculated fail states'
    # print_states(states)
    # s = bytearray('heshehishers she will lead a happy life with me')
    # matched_patterns = ac_inspect_string(states, s)
    # for pattern in matched_patterns:
    #     print pattern

    ac_inspect = ACInspect()
    ac_inspect.initialize_ac_inspect('rules_2000', RuleType.CLAMAV)
    print 'initialized ac inspect'
    fin = open('bigger.pcap', 'r')
    data = fin.read()
    data = bytearray(data)
    fin.close()
    ac_inspect.inspect(data)
    print_rules(ac_inspect.matched_rules)