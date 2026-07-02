// agent/src/features/entropy.cpp
#include "entropy.h"
#include <cmath>

float EntropyCalculator::ShannonEntropy(const std::vector<uint8_t>& data) {
    size_t n = data.size();
    if (n == 0) return 0.0f;

    size_t freq[256] = { 0 };
    for (uint8_t b : data) {
        freq[b]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(n);
    for (size_t count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / total;
        entropy -= p * log2(p);
    }

    return static_cast<float>(entropy);
}

float EntropyCalculator::CmdlineEntropy(const std::string& cmdline) {
    std::vector<uint8_t> data(cmdline.begin(), cmdline.end());
    return ShannonEntropy(data);
}
