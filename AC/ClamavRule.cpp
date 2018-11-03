#include <iostream>
#include <fstream>
#include <vector>

#include "ClamavRule.h"
#include "SignatureFragment.h"
#include "ACState.h"

using namespace std;


void print_hex(unsigned char value){
	unsigned int high = (value & 0xf0) >> 4;
	unsigned int low = (value & 0x0f);
	if(0 <= high && high <= 9){
		//printf("%d", high);
		cout << high;
	} else {
		char c = 'a' + high - 10;
		//printf("%c", c);
		cout << c;
	}

	if(0 <= low && low <= 9){
		//printf("%d", low);
		cout << low;
	} else {
		char c = 'a' + low - 10;
		//printf("%c", c);
		cout << c;
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
		//fprintf(stderr, "error in convert_hex_to_uint8, a = %d\n", (int) a);
		cout << "error in convert_hex_to_uint8" << endl;
	}

	if('0' <= b && b <= '9'){
		low = b - '0';
	} else if('a' <= b && b <= 'f'){
		low = b - 'a' + 10;
	} else if('A' <= b && b <= 'F'){
		low = b - 'A' + 10;
	} else {
		//fprintf(stderr, "error in convert_hex_to_uint8, b = %d\n", (int) b);
		cout << "error in convert_hex_to_uint8" << endl;
	}

	return (unsigned char) ((high << 4) | low);
}

void print_clamav_rules(vector<ClamavRule *> & rules){
	cout << rules.size() << endl;
	for(auto rule : rules){
		cout << rule->rulename << endl;
		cout << rule->sfs.size() << endl;
		for(auto sf : rule->sfs){
			cout << sf->type << endl;
			if(sf->type == RELATION_STAR){

			} else if(sf->type == RELATION_EXACT || sf->type == RELATION_MIN){
				cout << sf->min << endl;
			} else if(sf->type == RELATION_MAX){
				cout << sf->max << endl;
			} else {
				cout << sf->min << endl << sf->max << endl;
			}
			for(auto val : sf->s){
				print_hex(val);
			}
			cout << endl;
		}
	}
}

int read_clamav_rules(vector<ClamavRule *> & rules, string filename, int number_of_rules){
	ifstream fin(filename);
	int total_number_of_rules;
	fin >> total_number_of_rules;
	if(number_of_rules == -1){
		number_of_rules = total_number_of_rules;
	}
	//cout << "number_of_rules = " << number_of_rules << endl;
	int i;
	for(i = 0;i < number_of_rules;i++){
		ClamavRule * rule = new ClamavRule();
		rules.push_back(rule);
		// read rule name
		fin >> rule->rulename;
		// read the number of signature fragments
		int sfs_count;
		fin >> sfs_count;
		int j;
		for(j = 0;j < sfs_count;j++){
			// read the signature fragments
			SignatureFragment * sf = new SignatureFragment();
			sf->rule = rule;
			rule->sfs.push_back(sf);
			fin >> sf->type;
			if(sf->type == RELATION_STAR){

			} else if(sf->type == RELATION_EXACT || sf->type == RELATION_MIN){
				fin >> sf->min;
			} else if(sf->type == RELATION_MAX){
				fin >> sf->max;
			} else {
				fin >> sf->min;
				fin >> sf->max;
			}
			string tmp;
			fin >> tmp;
			int k = 0;
			for(k = 0;k + 1 < tmp.size(); k += 2){
				sf->s.push_back(convert_hex_to_uint8(tmp[k], tmp[k + 1]));
			}
		}
	}
	fin.close();
	return total_number_of_rules;
}

bool ClamavRule::is_matched(){
	if(sfs.size() == 1){
		SignatureFragment * sf = sfs[0];
		return sf->hit;
	} else if(sfs.size() < 1){
		return false;
	} else {
		int i;
		for(i = 1;i < sfs.size();i++){
			SignatureFragment * pre = sfs[i - 1];
			SignatureFragment * cur = sfs[i];
			if(pre->hit && cur->hit){
				// check distance relationship
				if(cur->type == RELATION_STAR){

				} else if(cur->type == RELATION_EXACT){
					if(cur->offset == pre->offset + cur->min + cur->s.size()){

					} else {
						return false;
					}
				} else if(cur->type == RELATION_MIN){
					if(cur->offset >= pre->offset + cur->min + cur->s.size()){

					} else {
						return false;
					}
				} else if(cur->type == RELATION_MAX){
					if(cur->offset <= pre->offset + cur->max + cur->s.size()){

					} else {
						return false;
					}
				} else {
					if(cur->offset >= pre->offset + cur->min + cur->s.size() && cur->offset <= pre->offset + cur->max + cur->s.size()){

					} else {
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