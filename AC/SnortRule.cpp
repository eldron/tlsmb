#include <vector>
#include <iostream>
#include <fstream>
#include "SnortRule.h"
#include "SnortContent.h"

using namespace std;

void print_snort_rules(vector<SnortRule *> & rules){
	// print total number of rules
	cout << rules.size() << endl;
	int i;
	for(i = 0;i < rules.size();i++){
		// print sid
		SnortRule * rule = rules[i];
		cout << rule->sid << endl;
		// the number of contents
		cout << rule->contents.size() << endl;
		int j;
		for(j = 0;j < rule->contents.size();j++){
			// print has_distance, distance, has_within and within
			SnortContent * sc = rule->contents[j];
			if(sc->has_distance){
				cout << "1" << endl;
				cout << sc->distance << endl;
			} else {
				cout << "0" << endl;
			}
			if(sc->has_within){
				cout << "1" << endl;
				cout << sc->within << endl;
			} else {
				cout << "0" << endl;
			}
			// print content len
			cout << sc->s.size() << endl;
			int k;
			for(k = 0;k < sc->s.size();k++){
				cout << (int) sc->s[k] << endl;
			}
		}
	}
}

int read_snort_rules(vector<SnortRule *> & rules, string filename, int number_of_rules){
	ifstream fin(filename);
	int total_number_of_rules;
	fin >> total_number_of_rules;
	int i;
	if(number_of_rules == -1){
		number_of_rules = total_number_of_rules;
	}
	for(i = 0;i < number_of_rules;i++){
		SnortRule * rule = new SnortRule();
		rules.push_back(rule);
		// read sid
		fin >> rule->sid;
		// read the number of contents
		int number_of_contents;
		fin >> number_of_contents;
		int j;
		for(j = 0;j < number_of_contents;j++){
			SnortContent * sc = new SnortContent();
			rule->contents.push_back(sc);
			sc->rule = rule;
			// for each content, read has_distance, distance, has_within and within
			int tmp;
			fin >> tmp;
			if(tmp){
				sc->has_distance = true;
				fin >> sc->distance;
			}
			fin >> tmp;
			if(tmp){
				sc->has_within = true;
				fin >> sc->within;
			}

			// read content len
			int len;
			fin >> len;
			int k;
			for(k = 0;k < len;k++){
				fin >> tmp;
				sc->s.push_back((unsigned char) tmp);
			}
		}
		
	}
	fin.close();
	return total_number_of_rules;
}

bool SnortRule::is_matched(){
	if(contents.size() == 1){
		SnortContent * sc = contents[0];
		return sc->hit;
	} else if(contents.size() < 1){
		return false;
	} else {
		int i = 1;
		for(i = 1;i < contents.size();i++){
			SnortContent * pre = contents[i - 1];
			SnortContent * cur = contents[i];
			if(pre->hit && cur->hit){
				if(cur->has_distance){
					if(cur->offset < pre->offset + cur->distance + cur->s.size()){
						return false;
					}
				}
				if(cur->has_within){
					if(cur->offset > pre->offset + cur->within + cur->s.size()){
						return false;
					}
				}
			} else {
				return false;
			}
		}
		return true;
	}
}