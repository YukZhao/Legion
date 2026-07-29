#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <signal.h>
#include <string>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include "hash_set.h"

using namespace std;

#define INITIAL_SEED 14;

extern uint32_t* random_mark_for_tracing_jue;
extern string* function_name_for_tracing_jue;
extern size_t tracing_array_size_jue;
extern uint32_t seed;
extern "C" void legion_set_symbolize_edges(int enabled);
extern "C" void legion_reset_trace_state();

hash_set* paths = nullptr;

extern "C" {
    int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
}

struct batch_options_t {
    string dir_path;
    string report_path;
    unsigned int jobs = 12;
    unsigned int seed_timeout = 0;
    string seed_report_dir;
};

struct active_seed_task_t {
    pid_t pid = -1;
    size_t seed_index = 0;
    string seed_file;
    string temp_report_path;
    chrono::steady_clock::time_point start_time;
};

enum report_section_t {
    REPORT_NONE,
    REPORT_EDGE,
    REPORT_PATH,
    REPORT_EDGE_TO_FUNC
};

static void print_usage(const char* argv0) {
    cout << "Usage: " << argv0
         << " --batch <folder_path> <report_path> [--jobs <count>] [--seed-timeout <seconds>] [--seed-report-dir <dir_path>]" << endl;
    cout << "   or: " << argv0
         << " <folder_path> <report_path> [--jobs <count>] [--seed-timeout <seconds>] [--seed-report-dir <dir_path>]" << endl;
}

static bool parse_positive_uint(const string& text, unsigned int& out) {
    try {
        size_t consumed = 0;
        unsigned long value = stoul(text, &consumed, 10);
        if (consumed != text.size()) {
            return false;
        }
        out = static_cast<unsigned int>(value);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parse_args(int argc, char** argv, batch_options_t& options) {
    int index = 1;
    if (argc >= 4 && string(argv[1]) == "--batch") {
        options.dir_path = argv[2];
        options.report_path = argv[3];
        index = 4;
    } else if (argc >= 3) {
        options.dir_path = argv[1];
        options.report_path = argv[2];
        index = 3;
    } else {
        return false;
    }

    while (index < argc) {
        string arg = argv[index];
        if (arg == "--jobs") {
            if (index + 1 >= argc) {
                return false;
            }
            unsigned int parsed = 0;
            if (!parse_positive_uint(argv[index + 1], parsed)) {
                return false;
            }
            options.jobs = (parsed == 0) ? 1 : parsed;
            index += 2;
            continue;
        }
        if (arg == "--seed-timeout") {
            if (index + 1 >= argc) {
                return false;
            }
            unsigned int parsed = 0;
            if (!parse_positive_uint(argv[index + 1], parsed)) {
                return false;
            }
            options.seed_timeout = parsed;
            index += 2;
            continue;
        }
        if (arg == "--seed-report-dir") {
            if (index + 1 >= argc) {
                return false;
            }
            options.seed_report_dir = argv[index + 1];
            index += 2;
            continue;
        }
        return false;
    }

    return true;
}

static bool readFile(const string& fileName, uint8_t*& buffer, size_t& bufferSize) {
    buffer = nullptr;
    bufferSize = 0;

    ifstream inputFile(fileName, ios::binary);
    if (!inputFile.is_open()) {
        return false;
    }

    inputFile.seekg(0, ios::end);
    size_t fileLength = inputFile.tellg();
    inputFile.seekg(0, ios::beg);

    bufferSize = fileLength;
    if (bufferSize > 0) {
        buffer = new uint8_t[bufferSize];
        inputFile.read(reinterpret_cast<char*>(buffer), bufferSize);
    }

    inputFile.close();
    return true;
}

static string seed_file_fingerprint(const string& file_name) {
    ifstream in(file_name, ios::binary);
    if (!in.is_open()) {
        return file_name;
    }

    uint64_t h = 1469598103934665603ULL;
    char buf[4096];
    while (in.good()) {
        in.read(buf, sizeof(buf));
        streamsize n = in.gcount();
        for (streamsize i = 0; i < n; ++i) {
            h ^= static_cast<unsigned char>(buf[i]);
            h *= 1099511628211ULL;
        }
    }
    return to_string(h);
}

static bool ensure_directory_recursive(const string& dir_path) {
    if (dir_path.empty()) {
        return false;
    }

    string partial;
    size_t index = 0;
    if (dir_path[0] == '/') {
        partial = "/";
        index = 1;
    }

    while (index <= dir_path.size()) {
        size_t next = dir_path.find('/', index);
        string component = dir_path.substr(index, next - index);
        if (!component.empty()) {
            if (!partial.empty() && partial.back() != '/') {
                partial.push_back('/');
            }
            partial += component;

            struct stat st;
            if (stat(partial.c_str(), &st) == 0) {
                if (!S_ISDIR(st.st_mode)) {
                    return false;
                }
            } else if (mkdir(partial.c_str(), 0755) != 0 && errno != EEXIST) {
                return false;
            }
        }

        if (next == string::npos) {
            break;
        }
        index = next + 1;
    }

    return true;
}

static bool copy_file_binary(const string& source_path, const string& dest_path) {
    ifstream in(source_path, ios::binary);
    if (!in.is_open()) {
        return false;
    }

    ofstream out(dest_path, ios::binary | ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    out << in.rdbuf();
    return in.good() || in.eof();
}

static string join_path(const string& dir_path, const string& file_name) {
    if (dir_path.empty()) {
        return file_name;
    }
    if (dir_path.back() == '/') {
        return dir_path + file_name;
    }
    return dir_path + "/" + file_name;
}

static bool run_single_test(const string& fileName) {
    uint8_t* buffer = nullptr;
    size_t bufferSize = 0;
    if (!readFile(fileName, buffer, bufferSize)) {
        cerr << "[LEGION] failed to read seed: " << fileName << endl;
        return false;
    }

    seed = INITIAL_SEED;
    LLVMFuzzerTestOneInput(buffer, bufferSize);
    if (paths != nullptr) {
        insert(paths, seed);
    }

    delete[] buffer;
    return true;
}

static bool write_sparse_report(const string& file_name, bool include_edge_to_func) {
    ofstream output(file_name);
    if (!output.is_open()) {
        cout << "[ERROR] failed to create file to write!!" << endl;
        return false;
    }

    output << "[EDGE]" << endl;
    for (size_t i = 1; i <= tracing_array_size_jue; i++) {
        if (random_mark_for_tracing_jue[i] > 0) {
            output << i << " " << random_mark_for_tracing_jue[i] << endl;
        }
    }

    output << "[PATH]" << endl;
    uint32_t** array = hashset_to_array(paths);
    for (uint32_t i = 0; i < paths->size; i++) {
        output << array[0][i] << " " << array[1][i] << endl;
    }
    free(array[0]);
    free(array[1]);
    free(array);

    output << "[EDGE TO FUNC]" << endl;
    if (include_edge_to_func) {
        for (size_t i = 1; i < tracing_array_size_jue; i++) {
            if (function_name_for_tracing_jue[i] != "") {
                output << i << " " << function_name_for_tracing_jue[i] << endl;
            }
        }
    }

    output.close();
    return true;
}

static bool write_batch_report(const string& file_name,
                               const vector<unsigned long>& edge_counts,
                               const unordered_map<uint32_t, unsigned long>& path_counts,
                               const vector<string>& edge_to_func) {
    ofstream output(file_name);
    if (!output.is_open()) {
        cout << "[ERROR] failed to create file to write!!" << endl;
        return false;
    }

    output << "[EDGE]" << endl;
    for (size_t i = 1; i < edge_counts.size(); i++) {
        output << i << " " << edge_counts[i] << endl;
    }

    output << "[PATH]" << endl;
    for (const auto& entry : path_counts) {
        output << entry.first << " " << entry.second << endl;
    }

    output << "[EDGE TO FUNC]" << endl;
    for (size_t i = 1; i < edge_to_func.size(); i++) {
        if (!edge_to_func[i].empty()) {
            output << i << " " << edge_to_func[i] << endl;
        }
    }

    output.close();
    return true;
}

static bool collect_seed_files(const string& dir_path, vector<string>& seed_files) {
    DIR* dir = opendir(dir_path.c_str());
    if (dir == NULL) {
        perror(dir_path.c_str());
        return false;
    }

    struct dirent* entry = nullptr;
    char file_path[PATH_MAX];
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) {
            continue;
        }
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path.c_str(), entry->d_name);
        seed_files.push_back(file_path);
    }

    closedir(dir);
    sort(seed_files.begin(), seed_files.end());
    return true;
}

static string create_temp_report_path() {
    char template_path[] = "/tmp/legion-seed-report-XXXXXX";
    int fd = mkstemp(template_path);
    if (fd == -1) {
        return "";
    }
    close(fd);
    return string(template_path);
}

static bool launch_seed_in_child(const string& seed_file,
                                 const string& temp_report_path,
                                 pid_t& child_pid) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return false;
    }

    if (pid == 0) {
        legion_set_symbolize_edges(0);
        legion_reset_trace_state();
        paths = create_hash_set();
        bool ok = run_single_test(seed_file) && write_sparse_report(temp_report_path, false);
        free_hash_set(paths);
        paths = nullptr;
        _exit(ok ? 0 : 1);
    }

    child_pid = pid;
    return true;
}

static void merge_seed_report(const string& report_path,
                              vector<unsigned long>& edge_counts,
                              unordered_map<uint32_t, unsigned long>& path_counts,
                              vector<string>& edge_to_func,
                              vector<unsigned int>* seed_edges = nullptr) {
    ifstream report(report_path);
    if (!report.is_open()) {
        return;
    }

    report_section_t section = REPORT_NONE;
    string line;
    while (getline(report, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }

        if (line[0] == '[') {
            if (line.rfind("[EDGE]", 0) == 0) {
                section = REPORT_EDGE;
            } else if (line.rfind("[PATH]", 0) == 0) {
                section = REPORT_PATH;
            } else if (line.rfind("[EDGE TO FUNC]", 0) == 0) {
                section = REPORT_EDGE_TO_FUNC;
            } else {
                section = REPORT_NONE;
            }
            continue;
        }

        if (section == REPORT_EDGE) {
            unsigned long id = 0;
            unsigned long count = 0;
            if (sscanf(line.c_str(), "%lu %lu", &id, &count) == 2 && id < edge_counts.size()) {
                if (seed_edges != nullptr && count > 0) {
                    seed_edges->push_back(static_cast<unsigned int>(id));
                }
                // Count corpus-level seed hits for edge frequency. The previous
                // dynamic-execution count (`edge_counts[id] += count`) let hot
                // loops in one seed dominate the low-frequency C4 threshold.
                if (count > 0) {
                    edge_counts[id] += 1;
                }
            }
            continue;
        }

        if (section == REPORT_PATH) {
            unsigned long hash = 0;
            unsigned long count = 0;
            if (sscanf(line.c_str(), "%lu %lu", &hash, &count) == 2) {
                path_counts[static_cast<uint32_t>(hash)] += count;
            }
            continue;
        }

        if (section == REPORT_EDGE_TO_FUNC) {
            size_t pos = line.find_first_of(" \t");
            if (pos == string::npos) {
                continue;
            }

            string id_text = line.substr(0, pos);
            string function_name = line.substr(pos + 1);
            size_t start = function_name.find_first_not_of(" \t");
            if (start == string::npos) {
                continue;
            }
            function_name = function_name.substr(start);

            unsigned int edge_id = 0;
            if (!parse_positive_uint(id_text, edge_id)) {
                continue;
            }

            if (edge_id < edge_to_func.size() && edge_to_func[edge_id].empty()) {
                edge_to_func[edge_id] = function_name;
            }
        }
    }

    report.close();
}

static bool select_seed_for_symbolization(const vector<unsigned int>& seed_edges,
                                          vector<unsigned char>& selected_edge_seen) {
    bool chosen = false;
    for (unsigned int id : seed_edges) {
        if (id >= selected_edge_seen.size()) {
            continue;
        }
        if (!selected_edge_seen[id]) {
            chosen = true;
            selected_edge_seen[id] = 1;
        }
    }
    return chosen;
}

static void harvest_edge_to_func(vector<string>& edge_to_func) {
    for (size_t i = 1; i < edge_to_func.size() && i < tracing_array_size_jue; ++i) {
        if (edge_to_func[i].empty() && !function_name_for_tracing_jue[i].empty()) {
            edge_to_func[i] = function_name_for_tracing_jue[i];
        }
    }
}

static void run_symbolization_pass(const vector<string>& mapping_seed_files,
                                   vector<string>& edge_to_func) {
    if (mapping_seed_files.empty()) {
        cout << "[LEGION] stage-2 symbolization skipped: no mapping seeds selected" << endl;
        return;
    }

    cout << "[LEGION] stage-2 symbolization pass will replay "
         << mapping_seed_files.size() << " seeds" << endl;

    legion_reset_trace_state();
    legion_set_symbolize_edges(1);
    paths = nullptr;

    size_t replayed = 0;
    size_t replay_failed = 0;
    for (size_t i = 0; i < mapping_seed_files.size(); ++i) {
        if ((i + 1) % 100 == 0 || i == 0) {
            cout << "[LEGION] stage-2 replay seed #" << (i + 1)
                 << " / " << mapping_seed_files.size() << endl;
        }
        if (run_single_test(mapping_seed_files[i])) {
            replayed++;
        } else {
            replay_failed++;
            cerr << "[LEGION] stage-2 replay failed: " << mapping_seed_files[i] << endl;
        }
    }

    harvest_edge_to_func(edge_to_func);
    legion_set_symbolize_edges(0);
    legion_reset_trace_state();

    cout << "[LEGION] stage-2 symbolization summary: replayed=" << replayed
         << ", failed=" << replay_failed << endl;
}

static bool run_batch(const batch_options_t& options) {
    vector<string> seed_files;
    if (!collect_seed_files(options.dir_path, seed_files)) {
        return false;
    }

    cout << "[LEGION] batch evaluate " << seed_files.size() << " seeds";
    cout << " with " << options.jobs << " parallel jobs";
    if (options.seed_timeout > 0) {
        cout << " with per-seed timeout " << options.seed_timeout << " seconds";
    }
    cout << endl;

    vector<unsigned long> edge_counts(tracing_array_size_jue + 1, 0);
    vector<string> edge_to_func(tracing_array_size_jue + 1);
    unordered_map<uint32_t, unsigned long> path_counts;
    vector<unsigned char> selected_edge_seen(tracing_array_size_jue + 1, 0);
    vector<string> mapping_seed_files;
    bool write_seed_reports = !options.seed_report_dir.empty();
    if (write_seed_reports && !ensure_directory_recursive(options.seed_report_dir)) {
        cerr << "[LEGION] failed to create per-seed report cache directory: "
             << options.seed_report_dir << endl;
        write_seed_reports = false;
    }

    size_t processed = 0;
    size_t timed_out = 0;
    size_t failed = 0;
    size_t next_seed_index = 0;
    vector<active_seed_task_t> active_tasks;
    const unsigned int jobs = (options.jobs == 0) ? 1 : options.jobs;

    auto finalize_task = [&](const active_seed_task_t& task, int status, bool was_timed_out) {
        if (!was_timed_out && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            vector<unsigned int> seed_edges;
            merge_seed_report(task.temp_report_path, edge_counts, path_counts, edge_to_func, &seed_edges);
            if (select_seed_for_symbolization(seed_edges, selected_edge_seen)) {
                mapping_seed_files.push_back(task.seed_file);
            }
            if (write_seed_reports) {
                const string cache_path = join_path(options.seed_report_dir,
                                                    seed_file_fingerprint(task.seed_file) + ".report");
                if (!copy_file_binary(task.temp_report_path, cache_path)) {
                    cerr << "[LEGION] failed to store per-seed report cache: "
                         << cache_path << endl;
                }
            }
            processed++;
        } else if (was_timed_out) {
            timed_out++;
            cerr << "[LEGION] seed timed out: " << task.seed_file << endl;
        } else {
            failed++;
            cerr << "[LEGION] seed failed: " << task.seed_file << endl;
        }

        unlink(task.temp_report_path.c_str());
    };

    while (next_seed_index < seed_files.size() || !active_tasks.empty()) {
        while (next_seed_index < seed_files.size() && active_tasks.size() < jobs) {
            if ((next_seed_index + 1) % 100 == 0 || next_seed_index == 0) {
                cout << "[LEGION] processing seed #" << (next_seed_index + 1)
                     << " / " << seed_files.size() << endl;
            }

            string temp_report_path = create_temp_report_path();
            if (temp_report_path.empty()) {
                cerr << "[LEGION] failed to create temporary report file" << endl;
                failed++;
                next_seed_index++;
                continue;
            }

            pid_t child_pid = -1;
            if (!launch_seed_in_child(seed_files[next_seed_index], temp_report_path, child_pid)) {
                cerr << "[LEGION] failed to launch seed: " << seed_files[next_seed_index] << endl;
                unlink(temp_report_path.c_str());
                failed++;
                next_seed_index++;
                continue;
            }

            active_seed_task_t task;
            task.pid = child_pid;
            task.seed_index = next_seed_index;
            task.seed_file = seed_files[next_seed_index];
            task.temp_report_path = temp_report_path;
            task.start_time = chrono::steady_clock::now();
            active_tasks.push_back(std::move(task));
            next_seed_index++;
        }

        bool made_progress = false;
        for (size_t i = 0; i < active_tasks.size();) {
            int status = 0;
            pid_t wait_rc = waitpid(active_tasks[i].pid, &status, WNOHANG);
            if (wait_rc == active_tasks[i].pid) {
                finalize_task(active_tasks[i], status, false);
                active_tasks.erase(active_tasks.begin() + i);
                made_progress = true;
                continue;
            }

            if (wait_rc < 0) {
                perror("waitpid");
                failed++;
                cerr << "[LEGION] seed failed: " << active_tasks[i].seed_file << endl;
                unlink(active_tasks[i].temp_report_path.c_str());
                active_tasks.erase(active_tasks.begin() + i);
                made_progress = true;
                continue;
            }

            if (options.seed_timeout > 0) {
                auto elapsed = chrono::duration_cast<chrono::seconds>(
                    chrono::steady_clock::now() - active_tasks[i].start_time).count();
                if (elapsed >= static_cast<long long>(options.seed_timeout)) {
                    kill(active_tasks[i].pid, SIGKILL);
                    waitpid(active_tasks[i].pid, &status, 0);
                    finalize_task(active_tasks[i], status, true);
                    active_tasks.erase(active_tasks.begin() + i);
                    made_progress = true;
                    continue;
                }
            }

            ++i;
        }

        if (!made_progress && !active_tasks.empty()) {
            usleep(100000);
        }
    }

    cout << "[LEGION] batch summary: processed=" << processed
         << ", timed_out=" << timed_out
         << ", failed=" << failed << endl;

    run_symbolization_pass(mapping_seed_files, edge_to_func);

    return write_batch_report(options.report_path, edge_counts, path_counts, edge_to_func);
}

int main(int argc, char** argv) {
    batch_options_t options;
    if (!parse_args(argc, argv, options)) {
        print_usage(argv[0]);
        return 1;
    }

    if (!run_batch(options)) {
        return 1;
    }

    return 0;
}
