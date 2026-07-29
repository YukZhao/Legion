#ifndef GRAPH_ANALYZER_H
#define GRAPH_ANALYZER_H

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <regex>
#include <vector>
#include <queue>

using namespace std;

extern unordered_map<string, int> nodes_label_to_id;
extern unordered_map<int, string> nodes_id_to_label;
extern vector<int> source_nodes;
extern vector<int> target_nodes;
extern vector<string> deep_functions;

vector<string> find_deep_functions(string filename);

#endif