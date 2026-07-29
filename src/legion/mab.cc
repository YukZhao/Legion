#include "mab.h"
#include <iostream>
#include <map>
#include <vector>
#include <random>
#include "global_record.h"

using namespace std;

// Assuming fuzzer_probabilities is defined in global_record.cc
extern map<string, double> fuzzer_probabilities;

// uint32_t select(vector<fuzzer_t> fuzzers) {
//     vector<double> probabilities;
//     vector<uint32_t> indices;

//     // Check for fuzzers with no recorded probability and select the first one found
//     for (uint32_t i = 0; i < fuzzers.size(); ++i) {
//         string fuzzer_id = fuzzers[i].label;
//         if (fuzzer_probabilities.find(fuzzer_id) == fuzzer_probabilities.end()) {
//             // fix
//             fuzzers.erase(fuzzers.begin() + i);
//             return i;
//         }
//         probabilities.push_back(fuzzer_probabilities[fuzzer_id]);
//         indices.push_back(i);
//     }

//     // If all fuzzers have recorded probabilities, perform weighted random sampling
//     random_device rd;
//     mt19937 gen(rd());
//     discrete_distribution<> dist(probabilities.begin(), probabilities.end());

//     return indices[dist(gen)];
// }
uint32_t select(const vector<fuzzer_t>& fuzzers) {
    vector<double> probabilities;
    vector<uint32_t> indices;

    // Check for fuzzers with no recorded probability and select the first one found
    for (uint32_t i = 0; i < fuzzers.size(); ++i) {
        string fuzzer_id = fuzzers[i].label;
        if (fuzzer_probabilities.find(fuzzer_id) == fuzzer_probabilities.end()) {
            return i;
        }
        probabilities.push_back(fuzzer_probabilities[fuzzer_id]);
        indices.push_back(i);
    }

    // If all fuzzers have recorded probabilities, perform weighted random sampling
    random_device rd;
    mt19937 gen(rd());
    discrete_distribution<> dist(probabilities.begin(), probabilities.end());

    return indices[dist(gen)];
}
