#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

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

#define RULE_TYPE_CLAMAV 0
#define RULE_TYPE_SNORT 1
#define RULE_TYPE_STRING 2

#define SERVER_ADDRESS "inspection_server"

unsigned char * mem_pool;
int mem_pool_max;
int mem_pool_idx;

struct list_node{
	void * ptr;
	struct list_node * next;
};

struct edge{
	unsigned char token;
	int state_number;// initialize to -2
};

struct state{
	int state_number;
	//struct edge edges[256];
	struct list_node * edges;
	int fail_state_number;
	struct list_node * output;
};

struct signature_fragment{
	int type;
	int min;
	int max;
	unsigned char * s;
	unsigned char hit;
	struct clamav_rule * rule;
	int len;
	int offset;// set during inspection
};

void initialize_signature_fragment(struct signature_fragment * sf){
	sf->type = 0;
	sf->min = 0;
	sf->max = 0;
	sf->s = NULL;
	sf->hit = 0;
	sf->rule = NULL;
	sf->len = 0;
	sf->offset = 0;
}

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

struct clamav_rule{
	char * rulename;
	int sfs_count;
	struct signature_fragment sfs[30];
	int hit;// for debug
};

struct snort_rule{
	int sid;
	int hit;
	struct snort_content contents[30];
	int content_list_len;
};

struct edge * get_edge(){
	if(mem_pool_idx + sizeof(struct edge) > mem_pool_max){
		fprintf(stderr, "mem not enough\n");
		return NULL;
	} else {
		struct edge * e = (struct edge *) &(mem_pool[mem_pool_idx]);
		mem_pool_idx += sizeof(struct edge);

		e->token = 0;
		e->state_number = -2;
		return e;
	}
}

void initialize_clamav_rule(struct clamav_rule * rule){
	rule->rulename = NULL;
	rule->sfs_count = 0;
	int i;
	for(i = 0;i < 30;i++){
		initialize_signature_fragment(&(rule->sfs[i]));
	}
	rule->hit = 0;
}

void initialize_mem_pool(){
	mem_pool_max = MAX_STATES * sizeof(struct state);
	mem_pool_max += LIST_POOL_SIZE;
	mem_pool_max += EDGE_POOL_SIZE;
	
	mem_pool = (unsigned char *) malloc(mem_pool_max);
	mem_pool_idx = 0;

	fprintf(stderr, "mem_pool_max = %d\n", mem_pool_max);
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

void push(struct list_node ** head, void * ptr){
	struct list_node * node = get_list_node();
	node->ptr = ptr;
	node->next = NULL;

	if(*head == NULL){
		*head = node;
	} else {
		node->next = *head;
		*head = node;
	}
}

void enqueue(struct list_node ** head, struct list_node ** tail, void * ptr){
	struct list_node * node = get_list_node();
	node->ptr = ptr;
	node->next = NULL;

	if(*head == NULL){
		*head = *tail = node;
	} else {
		(*tail)->next = node;
		*tail = node;
	}
}

struct state * initialize_states(){
	if(mem_pool_idx + MAX_STATES * sizeof(struct state) >= mem_pool_max){
		fprintf(stderr, "initialize_states: mem pool not enough\n");
		return NULL;
	}

	struct state * states = (struct state *) &(mem_pool[mem_pool_idx]);
	mem_pool_idx += MAX_STATES * sizeof(struct state);
	int i;
	for(i = 0;i < MAX_STATES;i++){
		states[i].state_number = i;
		// int j;
		// for(j = 0;j < 256;j++){
		// 	states[i].edges[j].token = j;
		// 	states[i].edges[j].state_number = -2;
		// }
		states[i].edges = NULL;
		states[i].fail_state_number = -1;
		states[i].output = NULL;
	}

	fprintf(stderr, "initialized states\n");
	return states;
}

struct signature_fragment * get_signature_fragment(){
	if(mem_pool_idx + sizeof(struct signature_fragment) >= mem_pool_max){
		fprintf(stderr, "memory pool not enough\n");
		return NULL;
	} else {
		struct signature_fragment * sf = (struct signature_fragment *) &(mem_pool[mem_pool_idx]);
		mem_pool_idx += sizeof(struct signature_fragment);

		sf->type = 0;
		sf->min = 0;
		sf->max = 0;
		sf->s = NULL;
		sf->hit = 0;
		sf->rule = NULL;
		sf->len = 0;
		sf->offset = 0;
		return sf;
	}
}


unsigned char * get_unsigned_char_array(int len){
	if(mem_pool_idx + len > mem_pool_max){
		fprintf(stderr, "mem pool not enough\n");
		return NULL;
	} else {
		unsigned char * tmp = &(mem_pool[mem_pool_idx]);
		mem_pool_idx += len;
		return tmp;
	}
}

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

struct clamav_rule * get_clamav_rule(){
	if(mem_pool_idx + sizeof(struct clamav_rule) > mem_pool_max){
		fprintf(stderr, "mem pool not enough\n");
		return NULL;
	} else {
		struct clamav_rule * rule = (struct clamav_rule *) &(mem_pool[mem_pool_idx]);
		mem_pool_idx += sizeof(struct clamav_rule);
		initialize_clamav_rule(rule);
		return rule;
	}
}

struct snort_rule * get_snort_rule(){
	if(mem_pool_idx + sizeof(struct snort_rule) > mem_pool_max){
		fprintf(stderr, "mem pool not enough\n");
		return NULL;
	} else {
		struct snort_rule * rule = (struct snort_rule *) &(mem_pool[mem_pool_idx]);
		mem_pool_idx += sizeof(struct snort_rule);

		//fprintf(stderr, "hello 1\n");

		rule->sid = 0;
		rule->hit = 0;
		rule->content_list_len = 0;
		//fprintf(stderr, "before init snort content\n");
		int i;
		for(i = 0;i < 30;i++){
			init_snort_content(&(rule->contents[i]));
		}

		//fprintf(stderr, "before return\n");
		return rule;
	}
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

unsigned char convert_hex_to_uint8(char a, char b){
	unsigned int high;
	unsigned int low;
	if('0' <= a && a <= '9'){
		high = a - '0';
	} else if('a' <= a && a <= 'f'){
		high = a - 'a' + 10;
	} else if('A' <= a && a <= 'F'){
		high = a - 'A' + 10;
	} else {
		fprintf(stderr, "error in convert_hex_to_uint8, a = %d\n", (int) a);
	}

	if('0' <= b && b <= '9'){
		low = b - '0';
	} else if('a' <= b && b <= 'f'){
		low = b - 'a' + 10;
	} else if('A' <= b && b <= 'F'){
		low = b - 'A' + 10;
	} else {
		fprintf(stderr, "error in convert_hex_to_uint8, b = %d\n", (int) b);
	}

	return (uint8_t) ((high << 4) | low);
}

// used to build the ac graph
int transit(struct state * states, int state_number, unsigned char token){
	struct list_node * head = states[state_number].edges;
	while(head){
		struct edge * e = (struct edge *) head->ptr;
		head = head->next;
		if(e->token == token){
			return e->state_number;
		}
	}
	return -1;
}

struct edge zero_state_edges[256];

void build_zero_state_edges(struct state * zero_state){
	int i;
	for(i = 0;i < 256;i++){
		zero_state_edges[i].token = i;
		zero_state_edges[i].state_number = -2;
	}

	struct list_node * head = zero_state->edges;
	while(head){
		struct edge * e = (struct edge *) head->ptr;
		zero_state_edges[e->token].state_number = e->state_number;
		head = head->next;
	}
}

int zero_goto_func(unsigned char token){
	int next_state = zero_state_edges[token].state_number;
	if(next_state == -2){
		return 0;
	} else {
		return next_state;
	}
}

int goto_func(struct state * states, int state_number, unsigned char token){
	if(state_number == 0){
		return zero_goto_func(token);
	} else {
		return transit(states, state_number, token);
	}
}
// // used to build the ac graph
// int transit(struct state * states, int state_number, unsigned char token){
// 	int next_state = states[state_number].edges[token].state_number;
// 	if(state_number == -2){
// 		return -1;
// 	} else {
// 		return next_state;
// 	}
// }

// int zero_goto_func(struct state * states, unsigned char token){
// 	int next_state = states[0].edges[token].state_number;
// 	if(next_state == -2){
// 		return 0;
// 	} else {
// 		return next_state;
// 	}
// }

// int goto_func(struct state * states, int state_number, unsigned char token){
// 	if(state_number == 0){
// 		return zero_goto_func(states, token);
// 	} else {
// 		return transit(states, state_number, token);
// 	}
// }
// void enter_clamav_sf(struct state * states, int * states_len, struct signature_fragment * sf){
// 	int current_state = 0;
// 	unsigned char * s = sf->s;
// 	int j = 0;
// 	while(j < sf->len){
// 		int next_state = transit(states, current_state, s[j]);
// 		if(next_state == -1){
// 			// did not find edge for the current pattern, add edges
// 			break;
// 		} else {
// 			j++;
// 			current_state = next_state;
// 		}
// 	}

// 	if(j == sf->len){
// 		// add to the output list
// 		push(&(states[current_state].output), sf);
// 	} else {
// 		// add edges for the following tokens
// 		while(j < sf->len){
// 			//states[current_state].edges[s[j]].state_number = *states_len;
// 			struct edge * newedge = get_edge();
// 			newedge->token = s[j];
// 			newedge->state_number = *states_len;
// 			push(&(states[current_state].edges), newedge);
// 			current_state = *states_len;
// 			(*states_len)++;
// 			j++;
// 		}
// 		// append to the output list
// 		push(&(states[current_state].output), sf);
// 	}
// }

// void enter_snort_content(struct state * states, int * states_len, struct snort_content * content){
// 	unsigned char * s = content->content;
// 	int s_len = content->content_len;

// 	int current_state = 0;
// 	int j = 0;
// 	while(j < content->content_len){
// 		int next_state = transit(states, current_state, s[j]);
// 		if(next_state == -1){
// 			// did not find edge for the current pattern, add edges
// 			break;
// 		} else {
// 			j++;
// 			current_state = next_state;
// 		}
// 	}

// 	if(j == content->content_len){
// 		// add to the output list
// 		push(&(states[current_state].output), content);
// 	} else {
// 		// add edges for the following tokens
// 		while(j < content->content_len){
// 			//states[current_state].edges[s[j]].state_number = *states_len;
// 			struct edge * newedge = get_edge();
// 			newedge->token = s[j];
// 			newedge->state_number = *states_len;
// 			push(&(states[current_state].edges), newedge);
// 			current_state = *states_len;
// 			(*states_len)++;
// 			j++;
// 		}
// 		// append to the output list
// 		push(&(states[current_state].output), content);
// 	}
// }

void enter_pattern(int rule_type, struct state * states, int * states_len, void * pattern, int pattern_len){
	int current_state = 0;
	int j = 0;
	while(j < pattern_len){
		int next_state = -1;
		if(rule_type == RULE_TYPE_STRING){
			char * s = (char *) pattern;
			next_state = transit(states, current_state, s[j]);
		} else if (rule_type == RULE_TYPE_CLAMAV){
			struct signature_fragment * sf = (struct signature_fragment *) pattern;
			next_state = transit(states, current_state, sf->s[j]);
		} else {
			struct snort_content * content = (struct snort_content *) pattern;
			next_state = transit(states, current_state, content->content[j]);
		}
		if(next_state == -1){
			// did not find edge for the current pattern, add edges
			break;
		} else {
			j++;
			current_state = next_state;
		}
	}

	if(j == pattern_len){
		// add to the output list
		push(&(states[current_state].output), pattern);
	} else {
		// add edges for the following tokens
		while(j < pattern_len){
			//states[current_state].edges[s[j]].state_number = *states_len;
			struct edge * newedge = get_edge();
			if(rule_type == RULE_TYPE_STRING){
				char * s = (char *) pattern;
				newedge->token = s[j];
			} else if(rule_type == RULE_TYPE_CLAMAV){
				struct signature_fragment * sf = (struct signature_fragment *) pattern;
				newedge->token = sf->s[j];
			} else {
				struct snort_content * content = (struct snort_content *) pattern;
				newedge->token = content->content[j];
			}
			
			newedge->state_number = *states_len;
			push(&(states[current_state].edges), newedge);
			current_state = *states_len;
			(*states_len)++;
			j++;
		}
		// append to the output list
		push(&(states[current_state].output), pattern);
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
			//states[current_state].edges[s[j]].state_number = *states_len;
			struct edge * newedge = get_edge();
			newedge->token = s[j];
			newedge->state_number = *states_len;
			push(&(states[current_state].edges), newedge);
			current_state = *states_len;
			(*states_len)++;
			j++;
		}
		// append to the output list
		push(&(states[current_state].output), s);
	}
}


void build_ac_graph_from_clamav_rules(struct state * states, int * states_len, struct list_node * rules, int rules_len){
	// states should be initialized
	struct list_node * head = rules;
	while(head){
		struct clamav_rule * rule = (struct clamav_rule *) head->ptr;
		head = head->next;
		int j;
		for(j = 0;j < rule->sfs_count;j++){
			struct signature_fragment * sf = &(rule->sfs[j]);
			//enter_clamav_sf(states, states_len, sf);
			enter_pattern(RULE_TYPE_CLAMAV, states, states_len, (void *) sf, sf->len);
		}
	}
}

void build_ac_graph_from_snort_rules(struct state * states, int * states_len, struct list_node * rules, int rules_len){
	// states should be initialized
	struct list_node * head = rules;
	while(head){
		struct snort_rule * rule = (struct snort_rule *) head->ptr;
		head = head->next;
		int j;
		for(j = 0;j < rule->content_list_len;j++){
			struct snort_content * content = &(rule->contents[j]);
			//enter_snort_content(states, states_len, content);
			enter_pattern(RULE_TYPE_SNORT, states, states_len, (void *) content, content->content_len);
		}
	}
}

void cal_failure_state(struct state * states, int states_len){
	struct state ** queue = (struct state **) malloc(states_len * sizeof(struct state *));
	int head = 0;
	int tail = 0;

	int i;
	struct list_node * n = states[0].edges;
	while(n){
		struct edge * e = (struct edge *) n->ptr;
		n = n->next;
		int state_number = e->state_number;
		states[state_number].fail_state_number = 0;
		queue[tail] = &(states[state_number]);
		tail++;
	}
	// for(i = 0;i < 256;i++){
	// 	int state_number = states[0].edges[i].state_number;
	// 	if(state_number != -2){
	// 		states[state_number].fail_state_number = 0;
	// 		queue[tail] = &(states[state_number]);
	// 		tail++;
	// 	}
	// }

	while(head < tail){
		struct state * current_state = queue[head];
		head++;
		struct list_node * n = current_state->edges;
		while(n){
			struct edge * e = (struct edge *) n->ptr;
			n = n->next;
			int state_number = e->state_number;
			if(state_number != -2){
				queue[tail] = &(states[state_number]);
				tail++;
				int fail_state = current_state->fail_state_number;
				while(1){
					if(goto_func(states, fail_state, e->token) == -1){
						fail_state = states[fail_state].fail_state_number;
					} else {
						break;
					}
				}
				states[e->state_number].fail_state_number = goto_func(states, fail_state, e->token);

				// modify the output list
				int tmp = states[e->state_number].fail_state_number;
				struct list_node * head = states[tmp].output;
				while(head){
					push(&(states[e->state_number].output), head->ptr);
					head = head->next;
				}
			}
		}
	}

	free(queue);
}

int check_clamav_rule(struct clamav_rule * rule){
	int i;
	for(i = 0;i < rule->sfs_count;i++){
		if(rule->sfs[i].hit == 0){
			return 0;
		}
	}

	// check distance relation ship between the signature fragments
	i = 1;
	while(i < rule->sfs_count){
		if(rule->sfs[i].type == RELATION_STAR){

		} else if(rule->sfs[i].type == RELATION_EXACT){
            if(rule->sfs[i - 1].offset + rule->sfs[i].len + rule->sfs[i].min == rule->sfs[i].offset){
                
			} else{
				return 0;
			}
		} else if(rule->sfs[i].type == RELATION_MIN){
            if(rule->sfs[i - 1].offset + rule->sfs[i].len + rule->sfs[i].min <= rule->sfs[i].offset){

			} else {
				return 0;
			}
		} else if(rule->sfs[i].type == RELATION_MAX){
            if(rule->sfs[i - 1].offset + rule->sfs[i].len + rule->sfs[i].max >= rule->sfs[i].offset){

			} else {
				return 0;
			}
		} else {
            if(rule->sfs[i - 1].offset + rule->sfs[i].len + rule->sfs[i].min <= rule->sfs[i].offset && 
			rule->sfs[i - 1].offset + rule->sfs[i].len + rule->sfs[i].max >= rule->sfs[i].offset){

			} else {
				return 0;
			}
		}
        i = i + 1;
	}

	return 1;
}

// void ac_inspect_string(struct state * states, unsigned char * s, int s_len){
// 	int state_number = 0;
// 	int i;
// 	for(i = 0;i < s_len;i++){
// 		while(goto_func(states, state_number, s[i]) == -1){
// 			state_number = states[state_number].fail_state_number;
// 		}
// 		state_number = goto_func(states, state_number, s[i]);
// 		if(states[state_number].output){
// 			printf("matched patterns are:\n");
// 			struct list_node * head = states[state_number].output;
// 			while(head){
// 				printf("%s\n", (char *) head->ptr);
// 				head = head->next;
// 			}
// 		}
// 	}
// }



void ac_inspect(int rule_type, struct state * states, int * global_state_number,
	unsigned char token, int offset, struct list_node ** matched_rules){
	
	while(goto_func(states, *global_state_number, token) == -1){
		*global_state_number = states[*global_state_number].fail_state_number;
	}
	*global_state_number = goto_func(states, *global_state_number, token);

	if(states[*global_state_number].output){
		// check if the corresponding rules are matched
		//fprintf(stderr, "ac_inspect: output is not null\n");
		struct list_node * head = states[*global_state_number].output;
		while(head){
			if(rule_type == RULE_TYPE_CLAMAV){
				struct signature_fragment * sf = (struct signature_fragment *) head->ptr;
				sf->hit = 1;
				sf->offset = offset;
				if(check_clamav_rule(sf->rule)){
					if(sf->rule->hit){

					} else {
						sf->rule->hit = 1;
						push(matched_rules, sf->rule);
					}
				}
			} else if (rule_type == RULE_TYPE_SNORT){
				//fprintf(stderr, "ac_inspect: rule type is snort\n");
				struct snort_content * content = (struct snort_content *) head->ptr;
				content->hit = 1;
				content->offset = offset;
				if(check_snort_rule(content->rule)){
					if(content->rule->hit){

					} else {
						content->rule->hit = 1;
						push(matched_rules, content->rule);
					}
				}
			} else {
				char * matched_pattern = (char *) head->ptr;
				printf("matched: %s\n", matched_pattern);
			}

			head = head->next;
		}

		// reset global state number
		*global_state_number = 0;
	}
}

void ac_inspect_string(struct state * states, unsigned char * s, int s_len){
	int global_state_number = 0;
	int i = 0;
	for(i = 0;i < s_len;i++){
		ac_inspect(RULE_TYPE_STRING, states, &global_state_number, s[i], i, NULL);
	}
}
// void snort_ac_inspect(struct state * states, int * global_state_number,
// 	unsigned char token, int offset, struct list_node ** matched_rules){
	
// 	while(goto_func(states, *global_state_number, token) == -1){
// 		*global_state_number = states[*global_state_number].fail_state_number;
// 	}
// 	*global_state_number = goto_func(states, *global_state_number, token);

// 	if(states[*global_state_number].output){
// 		// check if the corresponding rules are matched
// 		struct list_node * head = states[*global_state_number].output;
// 		while(head){
// 			struct snort_content * content = (struct snort_content *) head->ptr;
// 			content->hit = 1;
// 			content->offset = offset;
// 			if(check_snort_rule(content->rule)){
// 				if(content->rule->hit){

// 				} else {
// 					content->rule->hit = 1;
// 					push(matched_rules, content->rule);
// 				}
// 			}
// 			head = head->next;
// 		}

// 		// reset global state number
// 		*global_state_number = 0;
// 	}
// }

void read_type(FILE * fin, int * type, int * min, int * max){
	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10, fin);
	*type = atoi(c);
	if(*type == RELATION_STAR){

	} else if(*type == RELATION_MIN || *type == RELATION_EXACT){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
	} else if(*type == RELATION_MAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
	} else if(*type == RELATION_MINMAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
	}
}

// for testing
void print_type(int type, int min, int max){
	printf("%d\n", type);
	if(type == RELATION_STAR){

	} else if (type == RELATION_MIN || type == RELATION_EXACT){
		printf("%d\n", min);
	} else if (type == RELATION_MAX){
		printf("%d\n", max);
	} else {
		printf("%d\n%d\n", min, max);
	}
}

unsigned char * convert_hex_to_unsigned_char(char * s, struct signature_fragment * sf){
	int len = strlen(s) - 1;
	int k = 0;
	len = len / 2;
	sf->len = len;
	sf->s = get_unsigned_char_array(len);
	for(k = 0;k < len;k++){
		sf->s[k] = convert_hex_to_uint8(s[2 * k], s[2 * k + 1]);
	}
}

void print_hex(unsigned char value){
	unsigned int high = (value & 0xf0) >> 4;
	unsigned int low = (value & 0x0f);
	if(0 <= high && high <= 9){
		printf("%d", high);
	} else {
		char c = 'a' + high - 10;
		printf("%c", c);
	}

	if(0 <= low && low <= 9){
		printf("%d", low);
	} else {
		char c = 'a' + low - 10;
		printf("%c", c);
	}
}

// for testing
void print_clamav_rules(struct list_node * rules){
	// print total number of rules
	//printf("%d\n", total_number_of_rules);

	struct list_node * head = rules;
	while(head){
		struct clamav_rule * rule = (struct clamav_rule *) head->ptr;
		head = head->next;

		// print rule name
		printf("%s", rule->rulename);

		// print the number of signature fragments
		printf("%d\n", rule->sfs_count);

		int i;
		for(i = 0;i < rule->sfs_count;i++){
			// print type, min and max
			print_type(rule->sfs[i].type, rule->sfs[i].min, rule->sfs[i].max);

			// print hex string
			int j;
			for(j = 0;j < rule->sfs[i].len;j++){
				print_hex(rule->sfs[i].s[j]);
			}
			printf("\n");
		}
	}
}

int read_clamav_rules(char * filename, struct list_node ** rules, int number_of_rules){
	FILE * fin = fopen(filename, "r");
	// read total number of rules
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int total_number_of_rules = atoi(s);
	if(number_of_rules == -1){
		number_of_rules = total_number_of_rules;
	}

	struct list_node * tail = NULL;
	int i;
	for(i = 0;i < number_of_rules;i++){
		//fprintf(stderr, "reading rule %d\n", i);
		struct clamav_rule * rule = get_clamav_rule();
		enqueue(rules, &tail, rule);

		// read rule name
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		rule->rulename = (char *) get_unsigned_char_array(strlen(s) + 1);
		memcpy(rule->rulename, s, strlen(s) + 1);

		// read the number of signature fragments
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		rule->sfs_count = atoi(s);

		// read the signature fragments
		int j;
		for(j = 0;j < rule->sfs_count;j++){
			int type;
			int min;
			int max;
			read_type(fin, &type, &min, &max);

			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			convert_hex_to_unsigned_char(s, &(rule->sfs[j]));// s and len are set
			rule->sfs[j].rule = rule;
			rule->sfs[j].type = type;
			rule->sfs[j].min = min;
			rule->sfs[j].max = max;
		}
	}

	fclose(fin);
	return total_number_of_rules;
}

// for testing
void print_snort_rules(struct list_node * rules){
	// print total number of rules
	//printf("%d\n", total_number_of_rules);

	struct list_node * head = rules;
	while(head){
		struct snort_rule * rule = (struct snort_rule *) head->ptr;
		head = head->next;

		// print sid
		printf("sid = %d\n", rule->sid);

		// // print the number of contents
		// printf("%d\n", rule->content_list_len);

		// int i;
		// for(i = 0;i < rule->content_list_len;i++){
		// 	// print has_distance, distance, has_within and within
		// 	if(rule->contents[i].has_distance){
		// 		printf("1\n");
		// 		printf("%d\n", rule->contents[i].distance);
		// 	} else {
		// 		printf("0\n");
		// 	}

		// 	if(rule->contents[i].has_within){
		// 		printf("1\n");
		// 		printf("%d\n", rule->contents[i].within);
		// 	} else {
		// 		printf("0\n");
		// 	}

		// 	// print content_len
		// 	printf("%d\n", rule->contents[i].content_len);

		// 	// print content
		// 	int j = 0;
		// 	for(j = 0;j < rule->contents[i].content_len;j++){
		// 		printf("%d\n", rule->contents[i].content[j]);
		// 	}
		// }
	}
}

int read_snort_rules(char * filename, struct list_node ** rules, int number_of_rules){
	if(*rules != NULL){
		fprintf(stderr, "*rules is not NULL\n");
		return 0;
	}

	struct list_node * tail = NULL;

	FILE * fin = fopen(filename, "r");
	// read total number of rules
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int total_number_of_rules = atoi(s);
	//fprintf(stderr, "total number of rules = %d\n", total_number_of_rules);

	if(number_of_rules == -1){
		number_of_rules = total_number_of_rules;
	}

	int i;
	for(i = 0;i < number_of_rules;i++){
		//fprintf(stderr, "i = %d\n", i);

		struct snort_rule * rule = get_snort_rule();

		//fprintf(stderr, "got rule\n");

		// add rule to list
		enqueue(rules, &tail, rule);

		// read sid
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		rule->sid = atoi(s);

		//fprintf(stderr, "sid = %d\n", rule->sid);

		// read the number of contents
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		rule->content_list_len = atoi(s);

		int j;
		for(j = 0;j < rule->content_list_len;j++){
			// read has_distance, distance, has_within and within
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			int has_distance = atoi(s);
			rule->contents[j].has_distance = has_distance;
			if(has_distance){
				memset(s, '\0', LINELEN);
				fgets(s, LINELEN, fin);
				rule->contents[j].distance = atoi(s);
			}

			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			int has_within = atoi(s);
			rule->contents[j].has_within = has_within;
			if(has_within){
				memset(s, '\0', LINELEN);
				fgets(s, LINELEN, fin);
				rule->contents[j].within = atoi(s);
			}

			// read content len
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			int content_len = atoi(s);
			rule->contents[j].content_len = content_len;
			rule->contents[j].content = get_unsigned_char_array(content_len);
			// read content
			int k = 0;
			for(k = 0;k < content_len;k++){
				memset(s, '\0', LINELEN);
				fgets(s, LINELEN, fin);
				rule->contents[j].content[k] = (unsigned char) atoi(s);
			}

			rule->contents[j].rule = rule;
		}
	}

	fclose(fin);
	return total_number_of_rules;
}

// for testing
void print_state(struct state * s, int type){
	printf("state number = %d\n", s->state_number);
	printf("fail_state_number = %d\n", s->fail_state_number);
	struct list_node * head = s->edges;
	while(head){
		struct edge * e = (struct edge *) head->ptr;
		head = head->next;
		printf("token = %c, state_number = %d\n", (char) e->token, e->state_number);
	}

	if(type == RULE_TYPE_STRING){
		printf("output:\n");
		head = s->output;
		while(head){
			printf("%s\n", (char *) head->ptr);
			head = head->next;
		}
		printf("\n");
	} else if(type == RULE_TYPE_CLAMAV){

	} else {

	}
}

void print_states(struct state * states, int states_len, int type){
	int i;
	for(i = 0;i < states_len;i++){
		print_state(&(states[i]), type);
	}
}

struct rule_inspect{
	struct state * states;
	int states_len;
	struct list_node * rules;
	int number_of_rules;
	int global_state_number;
	struct list_node * matched_rules;
};

// number_of_rules should not be -1
void initialize_rule_inspect(int rule_type, struct rule_inspect * ins, char * filename, int number_of_rules){
	ins->states = initialize_states();
	ins->states_len = 1;
	ins->rules = NULL;
	if(rule_type == RULE_TYPE_CLAMAV){
		int total_number_of_rules = read_clamav_rules(filename, &(ins->rules), number_of_rules);
	} else if(rule_type == RULE_TYPE_SNORT) {
		int total_number_of_rules = read_snort_rules(filename, &(ins->rules), number_of_rules);
	} else {
		fprintf(stderr, "wrong rule type\n");
	}

	ins->number_of_rules = number_of_rules;
	if(rule_type == RULE_TYPE_CLAMAV){
		build_ac_graph_from_clamav_rules(ins->states, &(ins->states_len), 
			ins->rules, ins->number_of_rules);
	} else if(rule_type == RULE_TYPE_SNORT){
		build_ac_graph_from_snort_rules(ins->states, &(ins->states_len), 
			ins->rules, ins->number_of_rules);
	} else {
		fprintf(stderr, "wrong rule type\n");
	}
	build_zero_state_edges(&(ins->states[0]));
	cal_failure_state(ins->states, ins->states_len);
	ins->global_state_number = 0;
	ins->matched_rules = NULL;
}

int main(int argc, char ** args){
	if(argc != 4){
		fprintf(stderr, "usage: %s rule_type rule_file number_of_rules\n", args[0]);
		exit(1);
	}

	int rule_type = atoi(args[1]);
	char * rule_file = args[2];
	int number_of_rules = atoi(args[3]);
	initialize_mem_pool();
	fprintf(stderr, "mem pool initialized\n");

	struct rule_inspect ins;
	initialize_rule_inspect(rule_type, &ins, rule_file, number_of_rules);

	int server_sock;
	if((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		perror("create unix server socket failed");
		exit(1);
	} else {
		fprintf(stderr, "created server socket\n");
	}

	struct sockaddr_un server_address;
	server_address.sun_family = AF_UNIX;
	strcpy(server_address.sun_path, SERVER_ADDRESS);
	unlink(SERVER_ADDRESS);
	int server_address_len = sizeof(server_address.sun_family) + strlen(server_address.sun_path);
	if(bind(server_sock, &server_address, server_address_len) < 0){
		perror("bind unix server socket failed");
		exit(1);
	} else {
		fprintf(stderr, "bind server socket\n");
	}

	if(listen(server_sock, 5) < 0){
		perror("listen failed");
		exit(1);
	} else {
		fprintf(stderr, "server socket listening\n");
	}

	int client_sock;
	struct sockaddr_un client_address;
	int client_address_len;
	if((client_sock = accept(server_sock, &client_address, &client_address_len)) < 0){
		perror("accept failed");
		exit(1);
	} else {
		fprintf(stderr, "accepted client socket\n");
	}
	// we use stdio to read the socket
	FILE * fin = fdopen(client_sock, "r");
	int data_len;
	int offset = 0;
	unsigned char token;
	int i;
	unsigned char matched_reply[1];
	matched_reply[0] = 1;
	unsigned char no_match_reply[1];
	no_match_reply[0] = 0;

	unsigned char buffer[20000];
	while(1){
		// read data_len
		int high = fgetc(fin);
		int low = fgetc(fin);
		data_len = (high << 8) | low;
		fprintf(stderr, "data_len = %d\n", data_len);
		if(data_len > 0){
			// read data, perform inspection, send back result
			// for(i = 0;i < data_len;i++){
			// 	token = (unsigned char) fgetc(fin);
			// 	ac_inspect(rule_type, ins.states, &(ins.global_state_number), token, offset, &(ins.matched_rules));
			// }
			int len = fread(buffer, 1, data_len, fin);
			for(i = 0;i < len;i++){
				ac_inspect(rule_type, ins.states, &(ins.global_state_number), token, offset, &(ins.matched_rules));
				offset++;
			}
			if(ins.matched_rules){
				send(client_sock, matched_reply, 1, 0);
			} else {
				send(client_sock, no_match_reply, 1, 0);
			}
		} else {
			break;
		}
	}

	close(server_sock);
	return 0;
}
// int main(){
// 	initialize_mem_pool();
// 	fprintf(stderr, "mem pool initialized\n");

// 	// // test read snort rules
// 	// struct list_node * snort_rules = NULL;
// 	// int total_number_of_rules = read_snort_rules("snort_rules.txt", &snort_rules, -1);
// 	// print_snort_rules(snort_rules, total_number_of_rules);

// 	// test read clamav rules
// 	// struct list_node * clamav_rules = NULL;
// 	// int total_number_of_rules = read_clamav_rules("rules_2000", &clamav_rules, -1);
// 	// print_clamav_rules(clamav_rules);

// 	// test ac inspect string
// 	// char * he = "he";
// 	// char * she = "she";
// 	// char * his = "his";
// 	// char * hers = "hers";
// 	// struct state * states = initialize_states();
// 	// int states_len = 1;// zero state already exists
// 	// enter_pattern(RULE_TYPE_STRING, states, &states_len, he, strlen(he));
// 	// enter_pattern(RULE_TYPE_STRING, states, &states_len, she, strlen(she));
// 	// enter_pattern(RULE_TYPE_STRING, states, &states_len, his, strlen(his));
// 	// enter_pattern(RULE_TYPE_STRING, states, &states_len, hers, strlen(hers));
// 	// fprintf(stderr, "entered hers\n");

// 	// build_zero_state_edges(&(states[0]));
// 	// fprintf(stderr, "built zero state edges\n");

// 	// cal_failure_state(states, states_len);
// 	// print_states(states, states_len, RULE_TYPE_STRING);
// 	// char * hello = "hesheherhershishimit she is a good girl";
// 	// ac_inspect_string(states, hello, strlen(hello));

// 	// test clamav inspection
// 	// struct state * states = initialize_states();
// 	// int states_len = 1;
// 	// struct list_node * clamav_rules = NULL;
// 	// int total_number_of_rules = read_clamav_rules("rules_2000", &clamav_rules, -1);
// 	// build_ac_graph_from_clamav_rules(states, &states_len, clamav_rules, total_number_of_rules);
// 	// build_zero_state_edges(&(states[0]));
// 	// cal_failure_state(states, states_len);
// 	// //print_states(states, states_len, RULE_TYPE_CLAMAV);
// 	// int global_state_number = 0;
// 	// struct list_node * matched_rules = NULL;struct rule_inspect snort_ins;
// 	// initialize_rule_inspect(RULE_TYPE_SNORT, &snort_ins, "snort_rules.txt", 3368);

// 	// struct rule_inspect ins;
// 	// initialize_rule_inspect(RULE_TYPE_CLAMAV, &ins, "rules_2000", 2000);
// 	// FILE * fin = fopen("bigger.pcap", "r");
// 	// unsigned char token;
// 	// int offset = 0;
// 	// int value;
// 	// while((value = fgetc(fin)) != EOF){
// 	// 	token = (unsigned char) value; 
// 	// 	ac_inspect(RULE_TYPE_CLAMAV, ins.states, &(ins.global_state_number), token, offset, &(ins.matched_rules));
// 	// 	// printf("inspected %d\n", offset);
// 	// 	offset++;
// 	// }
// 	// print_clamav_rules(ins.matched_rules);
// 	// fclose(fin);

// 	// test snort inspection
// 	struct rule_inspect snort_ins;
// 	int offset = 0;
// 	initialize_rule_inspect(RULE_TYPE_SNORT, &snort_ins, "snort_rules.txt", 3368);
// 	fprintf(stderr, "initialized snort rules\n");
// 	FILE * fin = fopen("bigger.pcap", "r");
// 	int value;
// 	unsigned char token;
// 	while((value = fgetc(fin)) != EOF){
// 		token = (unsigned char) value;
// 		//fprintf(stderr, "inspecting %d\n", offset);
// 		ac_inspect(RULE_TYPE_SNORT, snort_ins.states, &(snort_ins.global_state_number), token, offset, &(snort_ins.matched_rules));
// 		//printf("inspected %d\n", offset);
// 		offset++;
// 	}
// 	print_snort_rules(snort_ins.matched_rules);
// 	fclose(fin);

// 	return 0;
// }

