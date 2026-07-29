#include "fuzzer_wrapper.h"
#include <iostream>
#include "fs_compat.h"

#define R_INIT 0
#define T_INIT 0

void add_fuzzer(vector<fuzzer_t>& scripts, string label, string filename, string script_name) {
    if (!check_binary(filename)) {
        cout << "[ERROR] the corresponding binary " << filename << " does not exist, will not use " << script_name << endl;
        return;
    }
    
    fuzzer_t fuzzer = {label, script_name, R_INIT, T_INIT};
    scripts.push_back(fuzzer);
   // cout << scripts.size() << endl;
}

int check_binary(string filename) {
    return filename == NO_BINARY || filesystem::exists(filename);    
}
