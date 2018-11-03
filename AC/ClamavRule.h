#include <vector>
using namespace std;

#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

class SignatureFragment;

class ClamavRule{
public:
	string rulename;
	vector<SignatureFragment *> sfs;
	bool hit;

	ClamavRule(){
		rulename = string();
		sfs = vector<SignatureFragment *>();
		hit = false;
	}

	bool is_matched();
};

void print_hex(unsigned char value);

unsigned char convert_hex_to_uint8(char a, char b);

void print_clamav_rules(vector<ClamavRule *> & rules);

int read_clamav_rules(vector<ClamavRule *> & rules, string filename, int number_of_rules);
