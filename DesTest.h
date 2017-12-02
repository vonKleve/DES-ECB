#pragma once

#include <vector>
#include <bitset>
#include "DES_ECB.h"

class DesTest : public Des
{
public:
	void test_actual_cipher(std::vector<bool> &portion);
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

	std::vector<bool> add_mod2(std::vector<bool> &a, std::vector<bool> &b);

	DesTest(std::vector<bool>& obj): mdes(Des(obj)) {};
	~DesTest();

private:
	Des mdes;
};

