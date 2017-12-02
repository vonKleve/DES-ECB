#pragma once

#include <vector>

class STables
{
	static std::vector<int> sTables;
public:

	STables() {};
	~STables() {};

	static bool check_amount();
	int operator() (int i, int j) { return sTables[i * 14 + j]; };
};

