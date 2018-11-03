#include <vector>
#include <iostream>

#include "ACState.h"
#include "SnortRule.h"
#include "SnortContent.h"
#include "ClamavRule.h"
#include "SignatureFragment.h"

using namespace std;

// int main(){
// 	vector<ClamavRule *> rules;
// 	string filename = "rules_96000";
// 	int total_number_of_rules = read_clamav_rules(rules, filename, -1);
// 	//cout << "after read_clamav_rules" << endl;
// 	//print_clamav_rules(rules);
// 	vector<ACState> states;
// 	initialize_states(states);
// 	// insert patterns
// 	for(auto rule : rules){
// 		for(auto sf : rule->sfs){
// 			insert_pattern(states, sf->s, sf);
// 		}
// 	}
// 	cal_failure_states(states);
// 	cout << "the number of states = " << states.size() << endl;

// 	return 0;
// }

int main(){
	vector<SnortRule *> rules;
	string filename = "snort_rules.txt";
	int total_number_of_rules = read_snort_rules(rules, filename, -1);
	vector<ACState> states;
	initialize_states(states);
	for(auto rule : rules){
		for(auto sc : rule->contents){
			insert_pattern(states, sc->s, sc);
		}
	}
	cal_failure_states(states);
	cout << "states.size() = " << states.size() << endl;
	return 0;
}
// int main(){
// 	vector<SnortRule *> rules;
// 	string filename = "snort_rules.txt";
// 	int total_number_of_rules = read_snort_rules(rules, filename, -1);
// 	//ofstream fout("tmp.txt");
// 	print_snort_rules(rules);
// 	//fout.close();

// 	return 0;
// }

// vector<unsigned char> string_to_vec(string & s){
// 	vector<unsigned char> v;
// 	for(auto c : s){
// 		v.push_back((unsigned char) c);
// 	}
// 	return v;
// }

// int main(){
// 	string he = "he";
// 	string she = "she";
// 	string his = "his";
// 	string hers = "hers";

// 	vector<unsigned char> vhe = string_to_vec(he);
// 	vector<unsigned char> vshe = string_to_vec(she);
// 	vector<unsigned char> vhis = string_to_vec(his);
// 	vector<unsigned char> vhers = string_to_vec(hers);

// 	vector<ACState> states;
// 	initialize_states(states);
// 	insert_pattern(states, vhe, &he);
// 	insert_pattern(states, vshe, &she);
// 	insert_pattern(states, vhis, &his);
// 	insert_pattern(states, vhers, &hers);

// 	print_states(states);

// 	cout << "before cal_failure_states" << endl;

// 	cal_failure_states(states);

// 	cout << "after cal_failure_states" << endl;
// 	print_states(states);

// 	string s = "falglahehisshehishers";
// 	int cur = 0;
// 	for(auto c : s){
// 		while(states[cur].edges.count(c) <= 0){
// 			cur = states[cur].fail_state_number;
// 		}
// 		cur = states[cur].edges[c];
// 		for(auto item : states[cur].output){
// 			cout << *((string *) item) << endl;
// 		}
// 	}
// 	return 0;
// }