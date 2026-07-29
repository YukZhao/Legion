#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <regex>
#include <vector>
#include <queue>

using namespace std;

unordered_map<string, int> nodes_label_to_id;
unordered_map<int, string> nodes_id_to_label;
vector<int> source_nodes;
vector<int> target_nodes;
vector<string> deep_functions;

string remove_align(string node_label, string pattern) {
    regex p(pattern);
    string replacement("");
    return regex_replace(node_label, p, replacement);
}

void process_line(string line) {
    
    regex node_regex("Node(\\d+) \\[label=\"(.*?)\".*\\]");
    smatch node_match;

    if (regex_search(line, node_match, node_regex)) {
        int node_id = stoi(node_match[1]);
        string node_label = node_match[2];
        //regex pattern("\\\\l");
        //string replacement("");
        //node_label = regex_replace(node_label, pattern, replacement);
        node_label = remove_align(node_label, "\\\\l");
        node_label = remove_align(node_label, "\\\\r");
        node_label = remove_align(node_label, "\\\\n");
        nodes_label_to_id[node_label] = node_id;
        nodes_id_to_label[node_id] = node_label;
        return;
    }
    
    regex edge_regex("Node(\\d+) -> Node(\\d+)");
    smatch edge_match;

    if (regex_search(line, edge_match, edge_regex)) {
        int source_node_id = stoi(edge_match[1]);
        int target_node_id = stoi(edge_match[2]);
        source_nodes.push_back(source_node_id);
        target_nodes.push_back(target_node_id);
    }
}

int parse_dot(string file) {
    string line;
    ifstream dot(file);
    if (dot.is_open()) {
        while (getline(dot, line)) {
            process_line(line);
        }
        dot.close();
        return 0;
    } else {
        printf("[ERROR] Unable to read dot file!!!!\n");
        return -1;
    }
    
} 

int find_root() {
    auto search = nodes_label_to_id.find("LLVMFuzzerTestOneInput");
    if (search == nodes_label_to_id.end()) {
        return -1;
    }
    return search -> second;
}


unordered_map<int, int> shortest_paths(int root) {
 //   cout << "gohere1!\n";
    unordered_map<int, vector<pair<int, int>>> graph;
    for (size_t i = 0; i < source_nodes.size(); i++) {
        graph[source_nodes[i]].push_back(make_pair(target_nodes[i], 1));
    
    }


    
 //   cout << "gohere2!\n";
    unordered_map<int, int> distances;
    unordered_map<int, int> unvisited;
    for (auto p : graph) {
        unvisited[p.first] = graph.size() + 10;
    }
    unvisited.erase(root);
    distances[root] = 0;
    int current = root;
   // cout << "gohere3!\n";
    while (!unvisited.empty()) {

      //  cout << "current: " << current << endl;
        
        int next;
        int shortest = INT32_MAX;

        for (auto p: graph[current]) {
           // cout << "first: " << current << endl;
            auto search = unvisited.find(p.first);
            bool found = search != unvisited.end();
            //cout << found << endl;
            if (found && unvisited[p.first] > distances[current] + p.second) {
            //    cout << "update!" << endl;
                unvisited[p.first] = distances[current] + p.second;
            }
        }

        for (auto v : unvisited) {
            //cout << "node: " << v.first << " " << v.second << endl;
            if (v.second < shortest) {
                shortest = v.second;
                next = v.first;
            }
        }
        distances[next] = shortest;
     //   cout << unvisited.size() << " " << next << endl;
        unvisited.erase(next);
     //   cout << unvisited.size() << endl;
        current = next;
    }

   // for (auto v : distances) {
   //     cout << v.first << " " << v.second << endl;
   // }
    return distances;
    
}

vector<string> find_deep_functions(string filename) {
    parse_dot(filename);
    int root = find_root();
    unordered_map<int, int> distances = shortest_paths(root);
    int sum = 0;
    for (const auto& p : distances) {
        sum += p.second;
    }
    int average = sum / distances.size();
    int threshold = average *  1.5;

    //cout << threshold << endl;

    for (const auto& p : distances) {
     //   cout << p.second << " " << threshold << endl;
        if (p.second > threshold) {
            deep_functions.push_back(nodes_id_to_label[p.first]);
        }
    }
    return deep_functions;
}