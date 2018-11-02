class ClamavRule;

class SignatureFragment{
public:
	int type;
	int min;
	int max;
	string s;
	bool hit;
	int offset;// set during inspection
	ClamavRule * rule;

	SignatureFragment(){
		type = min = max = 0;
		s = string();
		hit = false;
		offset = 0;
		rule = NULL;
	}
};