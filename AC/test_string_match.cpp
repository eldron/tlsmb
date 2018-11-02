#include <vector>
#include <iostream>

#include "ACState.h"
#include "SnortRule.h"

using namespace std;

int main(){
	vector<SnortRule *> rules;
	string filename = "snort_rules.txt";
	int total_number_of_rules = read_snort_rules(rules, filename, -1);
	//ofstream fout("tmp.txt");
	print_snort_rules(rules);
	//fout.close();

	return 0;
}
// int main(){
// 	string he = "he";
// 	string she = "she";
// 	string his = "his";
// 	string hers = "hers";

// 	vector<ACState> states;
// 	initialize_states(states);
// 	insert_pattern(states, he, &he);
// 	insert_pattern(states, she, &she);
// 	insert_pattern(states, his, &his);
// 	insert_pattern(states, hers, &hers);

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