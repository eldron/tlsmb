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
};

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
	struct list_node contents_list;
};

void init_snort_rule(struct snort_rule * rule){
	rule->sid = 0;
	rule->hit = 0;
	rule->contents_list.ptr = NULL;
	rule->contents_list.next = NULL;
}

int check_snort_rule(struct snort_rule * rule){
	struct list_node * node = &(rule->contents_list);
	// check if the first content is hit
	struct snort_content * first_content = (struct snort_content *) node->ptr;
	if(first_content && first_content->hit){
		struct list_node * prev_node = node;
		struct list_node * current_node = node->next;
		struct snort_content * prev_content = (struct snort_content *) prev_node->ptr;
		struct snort_content * current_content = (struct snort_content *) current_node->ptr;
		while(current_node){
			prev_content = (struct snort_content *) prev_node->ptr;
			current_content = (struct snort_content *) current_node->ptr;
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

			prev_node = current_node;
			current_node = current_node->next;
		}

		return 1;
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