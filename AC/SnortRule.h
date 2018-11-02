#include <fstream>
#include <vector>

using namespace std;

class SnortContent;

class SnortRule{
public:
	int sid;
	bool hit;
	vector<SnortContent *> contents;

	SnortRule(){
		sid = 0;
		hit = false;
		contents = vector<SnortContent *>();
	}
};

void print_snort_rules(vector<SnortRule *> & rules);

int read_snort_rules(vector<SnortRule *> & rules, string filename, int number_of_rules);