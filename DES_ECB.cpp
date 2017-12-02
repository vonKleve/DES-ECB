#include "stdafx.h"
#include "DES_ECB.h"

using std::cout;
using std::endl;

void show(std::vector<bool>& obj)
{
	for (int i = 0; i < obj.size(); i++)
	{
		cout << obj[i];
	}
	cout << endl;
}

void Des::actual_cipher(std::vector<bool>& iportion)
{
	std::vector<bool> portion(iportion);

	IP_exchange(portion);
	
	std::vector<bool> leftPart = std::vector<bool>(portion.begin(), portion.begin() + 32), 
		rightPart = std::vector<bool>(portion.begin() + 32, portion.end());

	std::vector<bool> extendedKey = get_extended_key();				
	std::vector<bool> cidi = get_k_zero(extendedKey);					

	int shiftCounter = 0;
	int shifts[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
	for (int i = 0; i < 16; i++)									
	{
		shift_left(cidi, shifts[shiftCounter]);						
		shiftCounter++;

		extendedKey = extract_keyi(cidi);		
		keyi.push_back(std::vector<bool>(extendedKey));
	}
	
	for (int i = 0; i < 16; i++) 
	{
		std::vector<bool> oldLeftPart(leftPart);

		leftPart = rightPart;
		std::vector<bool> tempFeistel = feistel(rightPart, keyi[i]);
		rightPart = add_mod2(oldLeftPart, tempFeistel);
	}

	for (int i = 0; i < 32; i++) {
		portion[i] = leftPart[i];
		portion[i + 32] = rightPart[i];
	}

	rev_IP_exchange(portion);

	iportion = portion;
}

void Des::actual_decipher(std::vector<bool>& iportion)
{
	std::vector<bool> portion(iportion);

	IP_exchange(portion);
	std::vector<bool> leftPart = std::vector<bool>(portion.begin(), portion.begin() + 32),
		rightPart = std::vector<bool>(portion.begin() + 32, portion.end());

	for (int i = 15; i >= 0; i--)
	{
		std::vector<bool> oldRightPart(rightPart);

		rightPart = leftPart;
		leftPart = add_mod2(oldRightPart, feistel(leftPart, keyi[i]));
	}

	for (int i = 0; i < 32; i++) {
		portion[i] = leftPart[i];
		portion[i + 32] = rightPart[i];
	}
	rev_IP_exchange(portion);

	iportion = portion;
}

void Des::IP_exchange(std::vector<bool>& obj)
{
	bool flag = true;
	static std::vector<int> ipTable = {
		58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
		57 ,49 ,41 ,33 ,25 ,17,	9 ,1 ,59 ,51 ,43 ,35 ,27 ,19 ,11 ,3,
		61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,63 ,55 ,47 ,39 ,31 ,23 ,15 ,7
	};
	std::vector<bool> mustBe(64);
	for (int i = 0; i < 64; i++)
	{
		int index = ipTable[i] - 1;
		mustBe[i] = obj[index];
	}
	obj = mustBe;
}

void Des::rev_IP_exchange(std::vector<bool>& obj)
{
	std::vector<int> revIpTable = {
		40 ,8 ,48 ,16 ,56 ,24 ,64, 32 ,39, 7, 47, 15, 55 ,23 ,63 ,31,
		38 ,6 ,46 ,14 ,54 ,22 ,62 ,30 ,37 ,5 ,45 ,13 ,53 ,21 ,61 ,29,
		36 ,4 ,44 ,12 ,52 ,20 ,60 ,28 ,35 ,3 ,43 ,11 ,51 ,19 ,59 ,27,
		34 ,2, 42 ,10 ,50 ,18 ,58 ,26 ,33 ,1 ,41 ,9 ,49 ,17 ,57 ,25
	};
	std::vector<bool> mustBe(64);
	for (int i = 0; i < 64; i++)
	{
		int index = revIpTable[i] - 1;
		mustBe[i] = obj[index];
	}
	obj = mustBe;
}

std::vector<bool> Des::get_extended_v(std::vector<bool>& op)
{
	std::vector<int> exchanges = {
		32 ,1 ,2 ,3 ,4 ,5,
		4 ,5 ,6 ,7 ,8 ,9,
		8 ,9 ,10 ,11 ,12 ,13,
		12 ,13 ,14 ,15 ,16 ,17,
		16 ,17 ,18 ,19 ,20 ,21,
		20 ,21 ,22 ,23 ,24 ,25,
		24 ,25 ,26 ,27 ,28 ,29,
		28 ,29 ,30 ,31 ,32 ,1
	};

	std::vector<bool> mustBe(48);
	for (int i = 0; i < 48; i++)
	{
		int index = exchanges[i] - 1;
		mustBe[i] = op[index];
	}

	return mustBe;
}

std::vector<bool> Des::get_extended_key()
{
	std::vector<bool> result;
	for (int i = 7; i < 56; i += 8)
	{
		bool cntrl = false;
		int sum = 0;
		for (int j = i - 7; j <= i; j++)
		{
			result.emplace_back(key[j]);
			sum += key[j];
		}
		if (sum % 2 == 0)
			cntrl = false;
		else
			cntrl = true;
		result.emplace_back(cntrl);
	}
	result.emplace_back(false);

	return result;
}

std::vector<bool> Des::get_k_zero(std::vector<bool>& obj)
{
	static std::vector<int> exchangeTable = {
		57 ,49 ,41 ,33 ,25 ,17 ,9 ,1 ,58 ,50 ,42 ,34 ,26 ,18,
		10 ,2 ,59 ,51 ,43 ,35 ,27 ,19 ,11 ,3 ,60 ,52 ,44 ,36,
		63 ,55 ,47 ,39 ,31 ,23 ,15 ,7 ,62 ,54 ,46 ,38 ,30 ,22,
		14 ,6 ,61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,28 ,20 ,12 ,4
	};
	std::vector<bool> mustBe(56);
	for (int i = 0; i < 56; i++)
	{
		int index = exchangeTable[i] - 1;
		mustBe[i] = obj[index];
	}
	return mustBe;
}

void Des::shift_left(std::vector<bool>& obj, int shiftSize)
{
	for (int i = 0; i < shiftSize; i++)
	{
		obj.emplace_back(*obj.begin());
		obj.erase(obj.begin());
	}
}

void Des::shift_right(std::vector<bool>& obj, int shiftSize)
{
	for (int i = 0; i < shiftSize; i++) 
	{
		obj.emplace(obj.begin(), *(obj.end() - 1) );
		obj.pop_back();
	}
}

std::vector<bool> Des::extract_keyi(std::vector<bool>& cidi)
{
	static std::vector<int> exchanges = {
		14 ,17 ,11 ,24 ,1 ,5 ,3 ,28 ,15 ,6 ,21 ,10 ,23 ,19 ,12 ,4,
		26 ,8 ,16 ,7 ,27 ,20 ,13 ,2 ,41 ,52 ,31 ,37 ,47 ,55 ,30 ,40,
		51 ,45 ,33 ,48 ,44 ,49 ,39 ,56 ,34 ,53 ,46 ,42 ,50 ,36 ,29 ,32
	};
	std::vector<bool> result(48);
	for (int i = 0; i < 48; i++)
	{
		int index = exchanges[i] - 1;
		result[i] = cidi[index];
	}
	return result;
}

std::vector<bool> Des::feistel(std::vector<bool>& op, std::vector<bool>& skey)
{
	std::vector<bool> result(op);

	result = get_extended_v(result);
	result = add_mod2(result, skey);
	result = s_exchange(result);
	p_exchange(result);

	return result;
}

void Des::p_exchange(std::vector<bool>& obj)
{
	std::vector<int> exchanges = {
		16, 7, 	20, 21, 29, 12, 28, 17,
		1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9,
		19, 13, 30, 6, 22, 11, 4, 25
	};
	std::vector<bool> result(obj);

	for (int i = 0; i < exchanges.size(); i++)
	{
		int index = exchanges[i] - 1;
		result[i] = obj[index];
	}

	obj = result;
}

std::vector<bool> Des::s_exchange(std::vector<bool>& was)
{
	bool flag = true;
	std::vector<int> S1 = {
		14 ,4 ,13 ,1 ,2 ,15 ,11 ,8 ,3 ,10 ,6 ,12 ,5 ,9 ,0 ,7,
		0 ,15 ,7 ,4 ,14 ,2 ,13 ,1 ,10,6 ,12 ,11 ,9 ,5 ,3 ,8,
		4 ,1 ,14 ,8 ,13 ,6 ,2 ,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0,
		15,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 ,13
	};
	std::vector<int> S2 = {
		15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
		3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
		0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
		13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
	};
	std::vector<int> S3 = {
		10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
		13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
		13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
		1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
	};
	std::vector<int> S4 = {
		7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
		13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
		10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
		3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
	};
	std::vector<int> S5 = {
		2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
		14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
		4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
		11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
	};
	std::vector<int> S6 = {
		12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
		10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
		9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
		4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
	};
	std::vector<int> S7 = {
		4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
		13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
		1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
		6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
	};
	std::vector<int> S8 = {
		13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
		1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
		7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
		2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
	};

	std::vector<std::vector<int>> sVectors;
	sVectors.push_back(S1);
	sVectors.push_back(S2);
	sVectors.push_back(S3);
	sVectors.push_back(S4);
	sVectors.push_back(S5);
	sVectors.push_back(S6);
	sVectors.push_back(S7);
	sVectors.push_back(S8);

	std::vector<bool> mustBe;
	for (int i = 0; i < 8; i++)
	{
		std::vector<bool> Bi(was.begin() + 6 * i, was.begin() + 6 + 6 * i);
		int row, column;
		row = Bi[0] * 2 + Bi[5];
		column = Bi[1] * 8 + Bi[2] * 4 + Bi[3] * 2 + Bi[4];

		int ttemp = sVectors[i][row * 16 + column];
		std::bitset<4> bttemp = ttemp;
		std::string num = bttemp.to_string();
		for (int i = 0; i < num.size(); i++)
		{
			mustBe.emplace_back(num[i] - '0');
		}
	}
	return mustBe;
}

std::vector<bool> Des::add_mod2(std::vector<bool>& a, std::vector<bool>& b)
{
	if (a.size() != b.size()) {
		throw std::logic_error("Vector sizes unequal.");
	}

	std::vector<bool> result(a.size());
	bool temp = 0;
	for (int i = 0; i < result.size(); i++)
	{
		result[i] = a[i] ^ b[i];
	}
	return result;
}

void Des::cipher(std::vector<bool> &obj)
{
	actual_cipher(obj);
}

void Des::decipher(std::vector<bool> &obj)
{
	actual_decipher(obj);
}
