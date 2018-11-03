#include <vector>

class ClamavRule;

class SignatureFragment{
public:
	int type;
	int min;
	int max;
	vector<unsigned char> s;
	bool hit;
	int offset;// set during inspection
	ClamavRule * rule;

	SignatureFragment(){
		type = min = max = 0;
		s = vector<unsigned char>();
		hit = false;
		offset = 0;
		rule = NULL;
	}
};