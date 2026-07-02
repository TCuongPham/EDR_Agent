// agent/include/entropy.h
#pragma once
#include <string>
#include <vector>

class EntropyCalculator {
public:
    static float ShannonEntropy(const std::vector<uint8_t>& data);
    static float CmdlineEntropy(const std::string& cmdline);
};
