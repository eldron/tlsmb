#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

#define SEG_SIZE 8
#define LIST_POOL_SIZE (100 * 1024 * 1024)
#define MAX_STATES (32 * 1024 * 1024)
#define EDGE_POOL_SIZE (100 * 1024 * 1024)
#define BUFFER_SIZE (30 * 1024 * 1024)
#define CONVERTED_BUFFER_SIZE (30 * 1024 * 1024)
#define MAX_RULE_NUMBER 100300
#define AC_BATCH_SIZE 2000

char * mem_pool;
int mem_pool_max;
int mem_pool_idx;

void initialize_mem_pool(){
	mem_pool_max = LIST_POOL_SIZE * sizeof(struct list_node);
	mem_pool_max += MAX_STATES * sizeof(struct state);
	
	mem_pool = (char *) malloc(mem_pool_max);
	mem_pool_idx = 0;
}

struct list_node{
	void * ptr;
	struct list_node * next;
};

void push(struct list_node * head, void * ptr){
	if(head->ptr == NULL){
		head->ptr = ptr;
	} else {
		struct list_node * node = get_list_node();
		node->ptr = ptr;
		node->next = head->next;
		head->next = node;
	}
}

struct list_node * get_list_node_helper(char * buffer, int *idx, int max){
	if(*idx + sizeof(struct list_node) < max){
		struct list_node * node = (struct list_node *) &(buffer[*idx]);
		*idx += sizeof(struct list_node);
		return node;
	} else {
		fprintf(stderr, "buffer not enough");
	}
}

struct list_node * get_list_node(){
	return get_list_node_helper(mem_pool, &mem_pool_idx, mem_pool_max);
}

struct edge{
	unsigned char token;
	int state_number;// initialize to -2
};

struct state{
	int state_number;
	struct edge edges[256];
	int fail_state_number;
	struct list_node output;
};

struct state * initialize_states(){
	struct state * states = (struct state *) &(mem_pool[mem_pool_idx]);
	mem_pool_idx += MAX_STATES * sizeof(struct state);
	int i;
	for(i = 0;i < MAX_STATES;i++){
		states[i].state_number = i;
		int j;
		for(j = 0;j < 256;j++){
			states[i].edges[j].token = j;
			states[i].edges[j].state_number = -2;
		}
		states[i].fail_state_number = -1;
		states[i].output.ptr = NULL;
		states[i].output.next = NULL;
	}
}

struct signature_fragment{
	int type;
	int min;
	int max;
	unsigned char * s;
	int hit;
	void * rule_ptr;
	unsigned char * converted;
	int len;
	int offset;// set during inspection
};

struct clamav_rule{
	char * rulename;
	int sfs_count;
	struct signature_fragment sfs[30];
	int hit;// for debug
};

struct snort_content{
	unsigned char * content;
	int content_len;
	int distance;
	int within;
	unsigned char has_distance;
	unsigned char has_within;
	unsigned char hit;
	int offset;// set during inspection
	struct snort_rule * rule;
};

void init_snort_content(struct snort_content * c){
	c->content = NULL;
	c->content_len = 0;
	c->has_distance = 0;
	c->has_within = 0;
	c->distance = 0;
	c->within = 0;
	c->hit = 0;
	c->offset = 0;
	c->rule = NULL;
}

struct snort_rule{
	int sid;
	unsigned char hit;
	struct snort_content contents[30];
	int content_list_len;
};

void init_snort_rule(struct snort_rule * rule){
	rule->sid = 0;
	rule->hit = 0;
	rule->content_list_len = 0;
}

int check_snort_rule(struct snort_rule * rule){
	if(rule->content_list_len > 0){
		// check if the first content is hit
		if(rule->contents[0].hit){
			int i = 1;
			while(i < rule->content_list_len){
				struct snort_content * prev_content = &(rule->contents[i - 1]);
				struct snort_content * current_content = &(rule->contents[i]);
				if(current_content->hit){
					// check distance and within
					if(current_content->has_distance){
						if(current_content->offset < prev_content->offset + current_content->distance + current_content->content_len){
							return 0;
						}
					}

					if(current_content->has_within){
						if(current_content->offset > prev_content->offset + current_content->within + current_content->content_len){
							return 0;
						}
					}
				} else {
					return 0;
				}
				i++;
			}
			
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

int char_to_int(char a){
	if('0' <= a && a <= '9'){
		return a - '0';
	} else if ('a' <= a && a <= 'f'){
		return a - 'a' + 10;
	} else {
		return a - 'A' + 10;
	}
}

int convert_hex_to_int(char a, char b){
	unsigned high = char_to_int(a);
	unsigned low = char_to_int(b);
	return (high << 4) | low;
}
// input: s, s_len
// output: content, content_len
void cal_content(char * s, int s_len, int * content, int * content_len){
	int hex_begin = 0;
	int i = 0;
	*content_len = 0;
	while(i < s_len){
		if(s[i] == '|'){
			if(hex_begin){
				hex_begin = 0;
			} else {
				hex_begin = 1;
			}
			i++;
		} else {
			if(hex_begin){
				if(s[i] == ' '){
					i++;
				} else {
					// convert 2 bytes to int value
					content[*content_len] = convert_hex_to_int(s[i], s[i + 1]);
					(*content_len)++;
					i = i + 2;
				}
			} else {
				// convert the current byte to int value
				content[*content_len] = char_to_int(s[i]);
				(*content_len)++;
				i++;
			}
		}
	}
}

// used to build the ac graph
int transit(struct state * states, int state_number, unsigned char token){
	int next_state = states[state_number].edges[token].state_number;
	if(state_number == -2){
		return -1;
	} else {
		return next_state;
	}
}

int zero_goto_func(struct state * states, unsigned char token){
	int next_state = states[0].edges[token].state_number;
	if(next_state == -2){
		return 0;
	} else {
		return next_state;
	}
}

int goto_func(struct state * states, int state_number, unsigned char token){
	if(state_number == 0){
		return zero_goto_func(states, token);
	} else {
		return transit(states, state_number, token);
	}
}
void enter_clamav_pattern(struct state * states, int * states_len, struct signature_fragment * sf){
	int current_state = 0;
	unsigned char * s = sf->s;
	int j = 0;
	while(j < sf->len){
		int next_state = transit(states, current_state, s[j]);
		if(next_state == -1){
			// did not find edge for the current pattern, add edges
			break;
		} else {
			j++;
			current_state = next_state;
		}
	}

	if(j == sf->len){
		// add to the output list
		push(&(states[current_state].output), sf);
	} else {
		// add edges for the following tokens
		while(j < sf->len){
			states[current_state].edges[s[j]].state_number = *states_len;
			current_state = *states_len;
			(*states_len)++;
			j++;
		}
		// append to the output list
		push(&(states[current_state].output), sf);
	}
}

void enter_snort_content(struct state * states, int * states_len, struct snort_content * content){
	int current_state = 0;
	unsigned char * s = content->content;
	int j = 0;
	while(j < content->content_len){
		int next_state = transit(states, current_state, s[j]);
		if(next_state == -1){
			// did not find edge for the current pattern, add edges
			break;
		} else {
			j++;
			current_state = next_state;
		}
	}

	if(j == content->content_len){
		// add to the output list
		push(&(states[current_state].output), content);
	} else {
		// add edges for the following tokens
		while(j < content->content_len){
			states[current_state].edges[s[j]].state_number = *states_len;
			current_state = *states_len;
			(*states_len)++;
			j++;
		}
		// append to the output list
		push(&(states[current_state].output), content);
	}
}

void enter_string_pattern(struct state * states, int * states_len, char * s, int s_len){
	int current_state = 0;
	int j = 0;
	while(j < s_len){
		int next_state = transit(states, current_state, s[j]);
		if(next_state == -1){
			// did not find edge for the current pattern, add edges
			break;
		} else {
			j++;
			current_state = next_state;
		}
	}

	if(j == s_len){
		// add to the output list
		push(&(states[current_state].output), s);
	} else {
		// add edges for the following tokens
		while(j < s_len){
			states[current_state].edges[s[j]].state_number = *states_len;
			current_state = *states_len;
			(*states_len)++;
			j++;
		}
		// append to the output list
		push(&(states[current_state].output), s);
	}
}

void build_ac_graph_from_clamav_rules(struct state * states, int * states_len, struct clamav_rule * rules, int rules_len){
	// states should be initialized
	int i;
	for(i = 0;i < rules_len;i++){
		int j;
		for(j = 0;j < rules[i].sfs_count;j++){
			struct signature_fragment * sf = &(rules[i].sfs[j]);
			enter_clamav_pattern(states, states_len, sf);
		}
	}
}

void build_ac_graph_from_snort_rules(struct state * states, int * states_len, struct snort_rule * rules, int rules_len){
	// states should be initialized
	int i;
	for(i = 0;i < rules_len;i++){
		int j;
		for(j = 0;j < rules[i].content_list_len;j++){
			struct snort_content * content = &(rules[i].contents[j]);
			enter_snort_content(states, states_len, content);
		}
	}
}

void cal_failure_state(struct state * states){
	struct state * queue[MAX_STATES];
	int head = 0;
	int tail = 0;

	int i;
	for(i = 0;i < 256;i++){
		int state_number = states[0].edges[i].state_number;
		if(state_number != -2){
			states[state_number].fail_state_number = 0;
			queue[tail] = &(states[state_number]);
			tail++;
		}
	}

	while(head < tail){
		struct state * current_state = queue[head];
		head++;
		for(i = 0;i < 256;i++){
			struct edge * e = &(current_state->edges[i]);
			int state_number = e->state_number;
			if(state_number != -2){
				queue[tail] = &(states[state_number]);
				int fail_state = current_state->fail_state_number;
				while(1){
					if(goto_func(states, fail_state, e->token) == -1){
						fail_state = states[fail_state].fail_state_number;
					}
				}
			}
		}
	}
}
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