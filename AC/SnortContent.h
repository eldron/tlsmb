class SnortRule;

class SnortContent{
public:
	vector<unsigned char> s;
	int distance;
	bool has_distance;
	int within;
	bool has_within;
	bool hit;
	int offset;// set during inspection
	SnortRule * rule;

	SnortContent(){
		s = vector<unsigned char>();
		distance = within = 0;
		has_within = has_distance = false;
		hit = false;
		offset = 0;
		rule = NULL;
	}
};