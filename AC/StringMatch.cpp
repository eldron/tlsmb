#include <unordered_map>
#include <queue>
#include <iostream>

#include "ACState.h"

using namespace std;

void initialize_states(vector<ACState> & states){
	ACState tmp;
	states.push_back(tmp);
}
// states should at least have state 0
// for string, ptr = &s
// for signature fragment, ptr = &sf
// for snort content, ptr = &sc
void insert_pattern(vector<ACState> & states, string & s, void * ptr){
	int i;
	int cur = 0;
	for(i = 0;i < s.size();i++){
		if(states[cur].edges.count(s[i]) > 0){
			cur = states[cur].edges[s[i]];
		} else {
			states[cur].edges[s[i]] = states.size();
			cur = states.size();
			ACState tmp;
			states.push_back(tmp);
		}
	}

	states[cur].output.push_back(ptr);
}

void cal_failure_states(vector<ACState> & states){
	// f(s) = 0 for all states of depth 1
	queue<int> q;
	unordered_map<unsigned char, int>::iterator itr = states[0].edges.begin();
	for(; itr != states[0].edges.end(); ++itr){
		states[itr->second].fail_state_number = 0;
		q.push(itr->second);
	}

	// initialize state 0
	int i;
	for(i = 0;i < 256;i++){
		if(states[0].edges.count(i) <= 0){
			states[0].edges[i] = 0;
		}
	}

	while(!q.empty()){
		int cur = q.front();
		//cout << "cur = " << cur << endl;
		q.pop();
		unordered_map<unsigned char, int>::iterator itr = states[cur].edges.begin();
		for(; itr != states[cur].edges.end(); ++itr){
			// a = itr->first
			// r = cur
			// g(r, a) = itr->second
			int state = states[cur].fail_state_number;
			while(true){
				if(states[state].edges.count(itr->first) > 0){
					// g(state, a) != failure
					break;
				} else {
					state = states[state].fail_state_number;
				}
			}
			// f(s) = g(state, a)
			states[itr->second].fail_state_number = states[state].edges[itr->first];
			int tmp = states[itr->second].fail_state_number;
			for(auto item : states[tmp].output){
				states[itr->second].output.push_back(item);
			}

			q.push(itr->second);
		}
	}
}

void print_states(vector<ACState> & states){
	int i;
	for(i = 0;i < states.size();i++){
		cout << i << " " << "fail state number = " << states[i].fail_state_number << endl;
		cout << "edges:" << endl;
		for(auto item : states[i].edges){
			cout << item.first << " " << item.second << endl;
		}
		cout << "output:" << endl;
		for(auto item : states[i].output){
			cout << *((string *) item) << endl;
		}
		cout << endl;
	}
}