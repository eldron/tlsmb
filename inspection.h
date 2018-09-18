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
#define MAX_STATES (64 * 1024 * 1024)
#define EDGE_POOL_SIZE (100 * 1024 * 1024)
#define BUFFER_SIZE (60 * 1024 * 1024)
#define CONVERTED_BUFFER_SIZE (60 * 1024 * 1024)
#define MAX_RULE_NUMBER 100300
#define AC_BATCH_SIZE 2000

#define RULE_TYPE_CLAMAV 0
#define RULE_TYPE_SNORT 1
#define RULE_TYPE_STRING 2

#define SERVER_ADDRESS "inspection_server"

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

struct rule_inspect{
	struct state * states;
	int states_len;
	struct list_node * rules;
	int number_of_rules;
	int global_state_number;
	struct list_node * matched_rules;
};

void initialize_signature_fragment(struct signature_fragment * sf);

struct edge * get_edge();

void initialize_clamav_rule(struct clamav_rule * rule);

void initialize_mem_pool();

struct list_node * get_list_node_helper(char * buffer, int *idx, int max);

struct list_node * get_list_node();

void push(struct list_node ** head, void * ptr);

void enqueue(struct list_node ** head, struct list_node ** tail, void * ptr);

struct state * initialize_states();

struct signature_fragment * get_signature_fragment();

unsigned char * get_unsigned_char_array(int len);

void init_snort_content(struct snort_content * c);

struct clamav_rule * get_clamav_rule();

struct snort_rule * get_snort_rule();

int check_snort_rule(struct snort_rule * rule);

unsigned char convert_hex_to_uint8(char a, char b);

int transit(struct state * states, int state_number, unsigned char token);

void build_zero_state_edges(struct state * zero_state);

int zero_goto_func(unsigned char token);

int goto_func(struct state * states, int state_number, unsigned char token);

void enter_pattern(int rule_type, struct state * states, int * states_len, void * pattern, int pattern_len);

void enter_string_pattern(struct state * states, int * states_len, char * s, int s_len);

void build_ac_graph_from_clamav_rules(struct state * states, int * states_len, struct list_node * rules, int rules_len);

void build_ac_graph_from_snort_rules(struct state * states, int * states_len, struct list_node * rules, int rules_len);

void cal_failure_state(struct state * states, int states_len);

int check_clamav_rule(struct clamav_rule * rule);

void ac_inspect(int rule_type, struct state * states, int * global_state_number,
	unsigned char token, int offset, struct list_node ** matched_rules);

void ac_inspect_string(struct state * states, unsigned char * s, int s_len);

void read_type(FILE * fin, int * type, int * min, int * max);

void print_type(int type, int min, int max);

unsigned char * convert_hex_to_unsigned_char(char * s, struct signature_fragment * sf);

void print_hex(unsigned char value);

void print_clamav_rules(struct list_node * rules);

int read_clamav_rules(char * filename, struct list_node ** rules, int number_of_rules);

void print_snort_rules(struct list_node * rules);

int read_snort_rules(char * filename, struct list_node ** rules, int number_of_rules);

void print_state(struct state * s, int type);

void print_states(struct state * states, int states_len, int type);

void initialize_rule_inspect(int rule_type, struct rule_inspect * ins, char * filename, int number_of_rules);

