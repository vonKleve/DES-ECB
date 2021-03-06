#include "stdafx.h"
#include <iostream>
#include "DES_ECB.h"
#include "STables.h"

using namespace std;

int main()
{
	//vector<bool> mkey(56, true);
	//vector<bool> message(64, false);
	vector<bool> mkey = { 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,  1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0 };
	vector<bool> message = { 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1,  1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1,  1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1 , 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1,  1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1 , 1 };
	cout << mkey.size() << " " << message.size() << endl;

	/*for (int i = 1; i < mkey.size(); i += 2)
	{
		mkey[i] = false;
	}*/

	vector<bool> sm = message;

	cout << "Key:\n";
	for (auto it : mkey)
	{
		cout << it;
	}
	cout << endl;
	Des obj(mkey);

	obj.cipher(message);
	cout << "Ciphered:\n";
	for (auto it : message)
	{
		cout << it;
	}
	cout << endl;
	obj.decipher(message);
	cout << endl << "Deciphered:\n";
	for (auto it : sm)
	{
		cout << it;
	}
	cout << endl;
	for(auto it : message)
	{
		cout << it;
	}
	cout << endl;

	system("pause");
    return 0;
}

