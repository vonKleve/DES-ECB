#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <bitset>
#include "STables.h"

class Des {
	void actual_cipher(std::vector<bool> &portion);
	void actual_decipher(std::vector<bool> &portion);

	std::vector<bool> get_extended_v(std::vector<bool> &obj);
	std::vector<bool> get_extended_key();
	std::vector<bool> extract_keyi(std::vector<bool> &cidi);
	std::vector<bool> get_k_zero(std::vector<bool> &obj);

	void shift_left(std::vector<bool> &obj, int shiftSize);
	void shift_right(std::vector<bool> &obj, int shiftSize);

	std::vector<bool> feistel(std::vector<bool> &op, std::vector<bool> &key);

	void IP_exchange(std::vector<bool> &obj);
	void rev_IP_exchange(std::vector<bool> &obj);
	void p_exchange(std::vector<bool>& obj);
	std::vector<bool> s_exchange(std::vector<bool>& obj);
public:
	Des() {};
	Des(std::vector<bool> &init) : key(init) { 
		keyi.reserve(16); };
	//void cypher(std::string &filename);
	void cipher(std::vector<bool> &obj);
	void decipher(std::vector<bool> &obj);

	static std::vector<bool> add_mod2(std::vector<bool> &a, std::vector<bool> &b);
private:
	std::vector<bool> key;
	std::vector<std::vector<bool>>keyi;
	static std::vector<int>exchangePTable;
};

