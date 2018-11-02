#include <vector>
#include <unordered_map>

using namespace std;

class ACState{
public:
	//int state_number;
	int fail_state_number;
	unordered_map<unsigned char, int> edges;
	vector<void *> output;

	ACState(){
		//state_number = 0;
		fail_state_number = 0;
		edges = unordered_map<unsigned char, int>();
		output = vector<void *>();
	}
};

void initialize_states(vector<ACState> & states);

// states should at least have state 0
// for string, ptr = &s
// for signature fragment, ptr = &sf
// for snort content, ptr = &sc
void insert_pattern(vector<ACState> & states, string & s, void * ptr);

void cal_failure_states(vector<ACState> & states);

void print_states(vector<ACState> & states);