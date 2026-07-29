#ifndef FUZZER_WRAPPER_H
#define FUZZER_WRAPPER_H

#include<string>
#include<vector>

using namespace std;

#define NO_BINARY "none"

typedef struct fuzzer_t {
    string label;
    string script;
    uint32_t reward;
    uint32_t trail_number;  
} fuzzer_wrapper;

void add_fuzzer(vector<fuzzer_t>& scripts, string label, string filename, string script_name);
int check_binary(string filename);

#endif