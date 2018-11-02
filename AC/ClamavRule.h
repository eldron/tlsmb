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
};