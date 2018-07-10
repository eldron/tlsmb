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
	struct edge edges[256];
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
	unsigned char * converted;
	int len;
	int offset;// set during inspection
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

void initialize_mem_pool(){
	mem_pool_max = 1024 * 1024 * 1024;
	
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
		states[i].output = NULL;
	}
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
		sf->converted = NULL;
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

// void init_snort_rule(struct snort_rule * rule){
// 	rule->sid = 0;
// 	rule->hit = 0;
// 	rule->content_list_len = 0;
// }

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

void ac_inspect_string(struct state * states, unsigned char * s, int s_len){
	int state_number = 0;
	int i;
	for(i = 0;i < s_len;i++){
		while(goto_func(states, state_number, s[i]) == -1){
			state_number = states[state_number].fail_state_number;
		}
		state_number = goto_func(states, state_number, s[i]);
		if(states[state_number].output){
			printf("matched patterns are:\n");
			struct list_node * head = states[state_number].output;
			while(head){
				printf("%s\n", (char *) head->ptr);
				head = head->next;
			}
		}
	}
}

void clamav_ac_inspect(struct state * states, int * global_state_number,
	unsigned char token, int offset, struct list_node ** matched_rules){
	
	while(goto_func(states, *global_state_number, token) == -1){
		*global_state_number = states[*global_state_number].fail_state_number;
	}
	*global_state_number = goto_func(states, *global_state_number, token);

	if(states[*global_state_number].output){
		// check if the corresponding rules are matched
		struct list_node * head = states[*global_state_number].output;
		while(head){
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
			head = head->next;
		}

		// reset global state number
		*global_state_number = 0;
	}
}

void snort_ac_inspect(struct state * states, int * global_state_number,
	unsigned char token, int offset, struct list_node ** matched_rules){
	
	while(goto_func(states, *global_state_number, token) == -1){
		*global_state_number = states[*global_state_number].fail_state_number;
	}
	*global_state_number = goto_func(states, *global_state_number, token);

	if(states[*global_state_number].output){
		// check if the corresponding rules are matched
		struct list_node * head = states[*global_state_number].output;
		while(head){
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
			head = head->next;
		}

		// reset global state number
		*global_state_number = 0;
	}
}

// void read_clamav_rules(char * buffer, char * filename, uint8_t * converted_buffer){
// 	int idx = 0;
// 	int converted_idx = 0;

// 	FILE * fin = fopen(filename, "r");
// 	// read the number of rules
// 	char s[LINELEN];
// 	memset(s, '\0', LINELEN);
// 	fgets(s, LINELEN, fin);
// 	number_of_rules = atoi(s);
// 	//fprintf(stderr, "number_of_rules = %d\n", number_of_rules);

// 	int i;
// 	for(i = 0;i < number_of_rules;i++){
// 		//fprintf(stderr, "reading rule %d\n", i);
// 		// read rule name
// 		memset(s, '\0', LINELEN);
// 		fgets(s, LINELEN, fin);
// 		if(idx + strlen(s) + 1 >= BUFFER_SIZE){
// 			fprintf(stderr, "BUFFER_SIZE too small\n");
// 			exit(1);
// 		}
// 		memcpy(&(buffer[idx]), s, strlen(s) + 1);
// 		short_rules[i].rulename = &(buffer[idx]);
// 		idx += strlen(s) + 1;

// 		// read the number of signature fragments
// 		memset(s, '\0', LINELEN);
// 		fgets(s, LINELEN, fin);
// 		short_rules[i].sfs_count = atoi(s);

// 		// read the signature fragments
// 		int j;
// 		for(j = 0;j < short_rules[i].sfs_count;j++){
// 			int type;
// 			int min;
// 			int max;
// 			read_type(fin, &type, &min, &max);

// 			memset(s, '\0', LINELEN);
// 			fgets(s, LINELEN, fin);
// 			if(idx + strlen(s) + 1 >= BUFFER_SIZE){
// 				fprintf(stderr, "BUFFER_SIZE too small\n");
// 				exit(1);
// 			}
// 			memcpy(&(buffer[idx]), s, strlen(s) + 1);
// 			//short_rules[i].sfs[j] = &(buffer[idx]);
// 			short_rules[i].sfs[j].s = &(buffer[idx]);
// 			short_rules[i].sfs[j].hit = 0;
// 			short_rules[i].sfs[j].rule_ptr = (void *) (&(short_rules[i]));
// 			short_rules[i].sfs[j].type = type;
// 			short_rules[i].sfs[j].min = min;
// 			short_rules[i].sfs[j].max = max;
// 			short_rules[i].sfs[j].hit = 0;
// 			short_rules[i].sfs[j].offset = 0;

// 			idx += strlen(s) + 1;
// 		}

// 		// convert the signature fragments
// 		for(j = 0;j < short_rules[i].sfs_count;j++){
// 			int len = strlen(short_rules[i].sfs[j].s) - 1;
// 			int k = 0;
// 			len = len / 2;
// 			short_rules[i].sfs[j].len = len;
// 			short_rules[i].sfs[j].converted = (uint8_t *) (&(converted_buffer[converted_idx]));
// 			for(k = 0;k < len;k++){
// 				converted_buffer[converted_idx] = convert_hex_to_uint8(short_rules[i].sfs[j].s[2 * k], short_rules[i].sfs[j].s[2 * k + 1]);
// 				converted_idx++;
// 				if(converted_idx >= CONVERTED_BUFFER_SIZE){
// 					fprintf(stderr, "CONVERTED_BUFFER_SIZE too small\n");
// 					exit(1);
// 				}
// 			}
// 		}
// 	}

// 	fclose(fin);
// }

// for testing
void print_snort_rules(struct list_node * rules, int total_number_of_rules){
	// print total number of rules
	printf("%d\n", total_number_of_rules);

	struct list_node * head = rules;
	while(head){
		struct snort_rule * rule = (struct snort_rule *) head->ptr;
		head = head->next;

		// print sid
		printf("%d\n", rule->sid);

		// print the number of contents
		printf("%d\n", rule->content_list_len);

		int i;
		for(i = 0;i < rule->content_list_len;i++){
			// print has_distance, distance, has_within and within
			if(rule->contents[i].has_distance){
				printf("1\n");
				printf("%d\n", rule->contents[i].distance);
			} else {
				printf("0\n");
			}

			if(rule->contents[i].has_within){
				printf("1\n");
				printf("%d\n", rule->contents[i].within);
			} else {
				printf("0\n");
			}

			// print content_len
			printf("%d\n", rule->contents[i].content_len);

			// print content
			int j = 0;
			for(j = 0;j < rule->contents[i].content_len;j++){
				printf("%d\n", rule->contents[i].content[j]);
			}
		}
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
		}
	}

	fclose(fin);
	return total_number_of_rules;
}

int main(){
	initialize_mem_pool();
	fprintf(stderr, "mem pool initialized\n");

	// test read snort rules
	struct list_node * snort_rules = NULL;
	int total_number_of_rules = read_snort_rules("snort_rules.txt", &snort_rules, -1);
	print_snort_rules(snort_rules, total_number_of_rules);
	return 0;
}