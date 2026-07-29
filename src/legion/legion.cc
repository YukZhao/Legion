#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <cerrno>
#include <fstream>
#include <functional>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fs_compat.h"
#include "graph_analyzer.h"
#include "fuzzer_wrapper.h"
#include "mab.h"
#include "global_record.h"
#include <map>
using namespace std;

#define GLOBAL_POOL_NAME "global"
#define INITIAL_POOL_NAME "initial"
#define GLOBAL_CMIN_INPUT_POOL_NAME ".global_cmin_input"
#define FUZZER_INPUT_SNAPSHOT_ROOT ".fuzzer_inputs"
#define DEFAULT_LEGION_SCRIPT_DIR "/Legion/scripts"

bool to_build = false;
bool to_run = false;
bool use_aflpp = false;
bool use_libfuzzer = false;
bool use_hongg = false;
bool use_radamsa = false;
bool use_qsym = false;
bool use_afl = false;
bool use_aflfast = false;
bool use_fairfuzz = false;
bool use_angora = false;
bool use_dictionary = false;
bool run_long = false;
bool do_minimize = false;
string compress_format;
string source_path;
string initial_seed_file;
uint32_t resource_unit_number;
uint32_t round_number;
uint32_t round_time;
uint32_t eval_seed_timeout = 0;
static const uint32_t MONITOR_TIME = 30;
//string working_directory;

static string legion_script_dir() {
    const char* env_dir = std::getenv("LEGION_SCRIPT_DIR");
    if (env_dir != nullptr && env_dir[0] != '\0') {
        return string(env_dir);
    }
    return DEFAULT_LEGION_SCRIPT_DIR;
}

static string script_path(const string& script_name) {
    return legion_script_dir() + "/" + script_name;
}

struct eval_seed_delta_t {
    string input_dir;
    filesystem::path manifest_path;
    vector<string> new_fingerprints;
    size_t total_files = 0;
    size_t new_files = 0;
};

struct enfuzz_worker_metrics_t {
    size_t raw_files = 0;
    size_t dedup_files = 0;
    unsigned long paths_total_sum = 0;
    unsigned long paths_total_max = 0;
};

struct libfuzzer_corpus_metrics_t {
    unsigned long corp_last = 0;
    unsigned long corp_max = 0;
};

struct worker_process_group_t {
    pid_t pid = -1;
    uint32_t units = 0;
    string mode;
    bool paused = false;
};

struct active_round_fuzzer_t {
    uint32_t fuzzer_index = 0;
    string label;
    string accum_seed_folder;
    string live_seed_folder;
    string monitor_report_path;
    uint32_t accounting_units = 0;
    uint32_t scheduled_units = 0;
    uint32_t next_worker_index = 1;
    double cumulative_monitor_reward = 0.0;
    bool active = false;
    vector<worker_process_group_t> groups;
};

static int run_command(string command);
void minimize_corpus(string seed_folder, string tmp_folder);
void refresh_global_cmin_input_pool();
void update_seed(string seed_folder, fuzzer_t fuzzer);
static void ensure_clean_directory(const filesystem::path& dir_path);
static void stop_persistent_round_fuzzer(active_round_fuzzer_t& state);
static bool write_empty_report(const string& report_name);
static bool prepare_incremental_eval_input(const string& fuzzer_label,
                                           size_t round,
                                           const string& local_seed_folder,
                                           const unordered_set<string>& round_initial_fingerprints,
                                           eval_seed_delta_t& delta);
static bool prepare_monitor_eval_input(const string& fuzzer_label,
                                       size_t round,
                                       const string& local_seed_folder,
                                       const unordered_set<string>& round_initial_fingerprints,
                                       eval_seed_delta_t& delta);
static void collect_active_round_outputs(active_round_fuzzer_t& state);

static string trim_copy(const string& text) {
    size_t start = text.find_first_not_of(" \t\r\n");
    if (start == string::npos) {
        return "";
    }
    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

static string sanitize_eval_label(const string& label) {
    string sanitized;
    sanitized.reserve(label.size());
    for (unsigned char ch : label) {
        if (isalnum(ch) || ch == '-' || ch == '_') {
            sanitized.push_back(static_cast<char>(ch));
        } else {
            sanitized.push_back('_');
        }
    }
    if (sanitized.empty()) {
        return "fuzzer";
    }
    return sanitized;
}

static string shell_quote(const string& value) {
    string quoted = "'";
    for (char ch : value) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(ch);
        }
    }
    quoted += "'";
    return quoted;
}

static string eval_file_fingerprint(const filesystem::path& seed_path) {
    ifstream in(seed_path, ios::binary);
    if (!in.is_open()) {
        return seed_path.string();
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

static bool read_named_ulong_from_stats(const filesystem::path& stats_path,
                                        const string& key,
                                        unsigned long& value) {
    ifstream in(stats_path);
    if (!in.is_open()) {
        return false;
    }

    string line;
    while (getline(in, line)) {
        size_t colon = line.find(':');
        if (colon == string::npos) {
            continue;
        }
        string name = trim_copy(line.substr(0, colon));
        if (name != key) {
            continue;
        }
        string raw_value = trim_copy(line.substr(colon + 1));
        size_t consumed = 0;
        try {
            value = stoul(raw_value, &consumed, 10);
            return consumed > 0;
        } catch (...) {
            return false;
        }
    }

    return false;
}

static size_t collect_immediate_files_with_fingerprints(const filesystem::path& dir_path,
                                                        unordered_set<string>& fingerprints) {
    if (!filesystem::exists(dir_path) || !filesystem::is_directory(dir_path)) {
        return 0;
    }

    size_t raw_files = 0;
    for (const auto& entry : filesystem::directory_iterator(dir_path)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        raw_files++;
        fingerprints.insert(eval_file_fingerprint(entry.path()));
    }
    return raw_files;
}

static void copy_immediate_files_to_dir(const filesystem::path& src_dir,
                                        const filesystem::path& dst_dir) {
    if (!filesystem::exists(src_dir) || !filesystem::is_directory(src_dir)) {
        return;
    }
    filesystem::create_directories(dst_dir);
    for (const auto& entry : filesystem::directory_iterator(src_dir)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        std::error_code ec;
        filesystem::copy_file(entry.path(),
                              dst_dir / entry.path().filename(),
                              filesystem::copy_options::overwrite_existing,
                              ec);
    }
}

static void copy_recursive_files_to_dir(const filesystem::path& src_dir,
                                        const filesystem::path& dst_dir) {
    if (!filesystem::exists(src_dir) || !filesystem::is_directory(src_dir)) {
        return;
    }
    filesystem::create_directories(dst_dir);
    for (const auto& entry : filesystem::recursive_directory_iterator(src_dir)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        std::error_code ec;
        filesystem::copy_file(entry.path(),
                              dst_dir / entry.path().filename(),
                              filesystem::copy_options::overwrite_existing,
                              ec);
    }
}

static enfuzz_worker_metrics_t collect_afl_like_metrics(const filesystem::path& output_dir) {
    enfuzz_worker_metrics_t metrics;
    if (!filesystem::exists(output_dir) || !filesystem::is_directory(output_dir)) {
        return metrics;
    }

    unordered_set<string> queue_fingerprints;
    for (const auto& entry : filesystem::directory_iterator(output_dir)) {
        if (!filesystem::is_directory(entry.path())) {
            continue;
        }

        const filesystem::path queue_dir = entry.path() / "queue";
        metrics.raw_files += collect_immediate_files_with_fingerprints(queue_dir, queue_fingerprints);

        unsigned long worker_paths_total = 0;
        if (read_named_ulong_from_stats(entry.path() / "fuzzer_stats",
                                        "paths_total",
                                        worker_paths_total)) {
            metrics.paths_total_sum += worker_paths_total;
            metrics.paths_total_max = max(metrics.paths_total_max, worker_paths_total);
        }
    }

    metrics.dedup_files = queue_fingerprints.size();
    return metrics;
}

static enfuzz_worker_metrics_t collect_libfuzzer_metrics(const filesystem::path& output_dir) {
    enfuzz_worker_metrics_t metrics;
    unordered_set<string> fingerprints;
    metrics.raw_files = collect_immediate_files_with_fingerprints(output_dir, fingerprints);
    metrics.dedup_files = fingerprints.size();
    return metrics;
}

static enfuzz_worker_metrics_t collect_radamsa_metrics(const filesystem::path& output_dir) {
    enfuzz_worker_metrics_t metrics;
    unordered_set<string> fingerprints;
    metrics.raw_files = collect_immediate_files_with_fingerprints(output_dir, fingerprints);
    metrics.dedup_files = fingerprints.size();
    return metrics;
}

static libfuzzer_corpus_metrics_t collect_libfuzzer_corpus_metrics(const filesystem::path& run_log_path) {
    libfuzzer_corpus_metrics_t metrics;
    ifstream in(run_log_path);
    if (!in.is_open()) {
        return metrics;
    }

    string line;
    while (getline(in, line)) {
        size_t pos = line.find("corp:");
        if (pos == string::npos) {
            continue;
        }
        pos += 5;
        while (pos < line.size() && isspace(static_cast<unsigned char>(line[pos]))) {
            pos++;
        }
        size_t end = pos;
        while (end < line.size() && isdigit(static_cast<unsigned char>(line[end]))) {
            end++;
        }
        if (end == pos) {
            continue;
        }
        unsigned long corp = 0;
        try {
            corp = stoul(line.substr(pos, end - pos));
        } catch (...) {
            continue;
        }
        metrics.corp_last = corp;
        metrics.corp_max = max(metrics.corp_max, corp);
    }
    return metrics;
}

static size_t count_recursive_seed_files(const filesystem::path& root,
                                         unordered_set<string>* fingerprints = nullptr) {
    if (!filesystem::exists(root) || !filesystem::is_directory(root)) {
        return 0;
    }

    size_t raw_files = 0;
    for (const auto& entry : filesystem::recursive_directory_iterator(root)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        if (entry.path().filename() == "manifest.txt") {
            continue;
        }
        raw_files++;
        if (fingerprints != nullptr) {
            fingerprints->insert(eval_file_fingerprint(entry.path()));
        }
    }
    return raw_files;
}

static void record_enfuzz_path_metrics(size_t round, const vector<fuzzer_t>& fuzzers) {
    map<string, enfuzz_worker_metrics_t> by_fuzzer;

    for (const auto& fuzzer : fuzzers) {
        if (fuzzer.label == "AFL") {
            by_fuzzer[fuzzer.label] = collect_afl_like_metrics(filesystem::path("run_afl") / "output");
        } else if (fuzzer.label == "AFLFast") {
            by_fuzzer[fuzzer.label] = collect_afl_like_metrics(filesystem::path("run_aflfast") / "output");
        } else if (fuzzer.label == "FairFuzz") {
            by_fuzzer[fuzzer.label] = collect_afl_like_metrics(filesystem::path("run_fairfuzz") / "output");
        } else if (fuzzer.label == "QSYM") {
            by_fuzzer[fuzzer.label] = collect_afl_like_metrics(filesystem::path("run_qsym") / "output");
        } else if (fuzzer.label == "LibFuzzer") {
            by_fuzzer[fuzzer.label] = collect_libfuzzer_metrics(filesystem::path("run_lib") / "output" / "queue");
        } else if (fuzzer.label == "Radamsa") {
            by_fuzzer[fuzzer.label] = collect_radamsa_metrics(filesystem::path("run_radamsa") / "output");
        }
    }

    libfuzzer_corpus_metrics_t libfuzzer_corpus = collect_libfuzzer_corpus_metrics("run.log");

    size_t display_paths_sum_worker = 0;
    size_t display_paths_sum_base_max = 0;
    size_t display_paths_sum_base_dedup = 0;

    for (const auto& entry : by_fuzzer) {
        const string& label = entry.first;
        const enfuzz_worker_metrics_t& metrics = entry.second;
        if (label == "AFL" || label == "AFLFast" || label == "FairFuzz" || label == "QSYM") {
            display_paths_sum_worker += metrics.paths_total_sum;
            display_paths_sum_base_max += metrics.paths_total_max;
            display_paths_sum_base_dedup += metrics.dedup_files;
        } else if (label == "LibFuzzer") {
            unsigned long current = (libfuzzer_corpus.corp_last > 0)
                ? libfuzzer_corpus.corp_last
                : static_cast<unsigned long>(metrics.dedup_files);
            display_paths_sum_worker += current;
            display_paths_sum_base_max += current;
            display_paths_sum_base_dedup += metrics.dedup_files;
        } else if (label == "Radamsa") {
            display_paths_sum_worker += metrics.raw_files;
            display_paths_sum_base_max += metrics.dedup_files;
            display_paths_sum_base_dedup += metrics.dedup_files;
        }
    }

    unordered_set<string> global_fingerprints;
    size_t global_files = count_recursive_seed_files(GLOBAL_POOL_NAME, &global_fingerprints);

    unordered_set<string> archive_fingerprints;
    size_t archive_files = count_recursive_seed_files("archive", &archive_fingerprints);

    unordered_set<string> sync_delta_fingerprints;
    size_t sync_delta_files = count_recursive_seed_files(".sync_delta", &sync_delta_fingerprints);

    const filesystem::path metrics_dir = "metrics";
    const filesystem::path csv_path = metrics_dir / "enfuzz_paths.csv";
    filesystem::create_directories(metrics_dir);

    bool need_header = !filesystem::exists(csv_path) || filesystem::file_size(csv_path) == 0;
    ofstream out(csv_path, ios::app);
    if (!out.is_open()) {
        std::cout << "[LEGION] warning: failed to write EnFuzz path metrics to "
                  << csv_path << endl;
        return;
    }

    vector<string> labels = {"AFL", "AFLFast", "FairFuzz", "QSYM", "LibFuzzer", "Radamsa"};
    if (need_header) {
        out << "round";
        for (const auto& label : labels) {
            string prefix = sanitize_eval_label(label);
            out << "," << prefix << "_raw_files";
            out << "," << prefix << "_dedup_files";
            out << "," << prefix << "_paths_total_sum";
            out << "," << prefix << "_paths_total_max";
        }
        out << ",libfuzzer_corp_last";
        out << ",libfuzzer_corp_max";
        out << ",display_paths_sum_worker";
        out << ",display_paths_sum_base_max";
        out << ",display_paths_sum_base_dedup";
        out << ",global_pool_files";
        out << ",global_pool_fingerprints";
        out << ",archive_files";
        out << ",archive_fingerprints";
        out << ",sync_delta_files";
        out << ",sync_delta_fingerprints";
        out << endl;
    }

    out << round;
    for (const auto& label : labels) {
        const enfuzz_worker_metrics_t metrics = by_fuzzer.count(label) > 0
            ? by_fuzzer[label]
            : enfuzz_worker_metrics_t();
        out << "," << metrics.raw_files;
        out << "," << metrics.dedup_files;
        out << "," << metrics.paths_total_sum;
        out << "," << metrics.paths_total_max;
    }
    out << "," << libfuzzer_corpus.corp_last;
    out << "," << libfuzzer_corpus.corp_max;
    out << "," << display_paths_sum_worker;
    out << "," << display_paths_sum_base_max;
    out << "," << display_paths_sum_base_dedup;
    out << "," << global_files;
    out << "," << global_fingerprints.size();
    out << "," << archive_files;
    out << "," << archive_fingerprints.size();
    out << "," << sync_delta_files;
    out << "," << sync_delta_fingerprints.size();
    out << endl;

    std::cout << "[LEGION] recorded EnFuzz-style path metrics for round #" << round
              << ": worker-sum=" << display_paths_sum_worker
              << ", base-max-sum=" << display_paths_sum_base_max
              << ", base-dedup-sum=" << display_paths_sum_base_dedup
              << ", global-fingerprints=" << global_fingerprints.size()
              << ", archive-fingerprints=" << archive_fingerprints.size()
              << ", sync-delta-fingerprints=" << sync_delta_fingerprints.size()
              << endl;
}

static filesystem::path eval_seed_report_cache_dir(const string& fuzzer_label, size_t round) {
    return filesystem::path(".eval_seed_reports") /
           (sanitize_eval_label(fuzzer_label) + "_" + to_string(round));
}

static filesystem::path eval_seed_report_cache_path(const string& fuzzer_label,
                                                    size_t round,
                                                    const string& fingerprint) {
    return eval_seed_report_cache_dir(fuzzer_label, round) /
           (fingerprint + ".report");
}

static bool load_seen_fingerprints(const filesystem::path& manifest_path,
                                   unordered_set<string>& seen_fingerprints) {
    if (!filesystem::exists(manifest_path)) {
        return true;
    }

    ifstream in(manifest_path);
    if (!in.is_open()) {
        return false;
    }

    string line;
    while (getline(in, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (!line.empty()) {
            seen_fingerprints.insert(line);
        }
    }
    return true;
}

static bool append_seen_fingerprints(const filesystem::path& manifest_path,
                                     const vector<string>& fingerprints) {
    if (fingerprints.empty()) {
        return true;
    }

    ofstream out(manifest_path, ios::app);
    if (!out.is_open()) {
        return false;
    }

    for (const auto& fp : fingerprints) {
        out << fp << endl;
    }
    return true;
}

static void archive_round_new_seeds(const string& fuzzer_label,
                                    size_t round,
                                    const string& local_seed_folder,
                                    const unordered_set<string>& round_initial_fingerprints) {
    if (!filesystem::exists(local_seed_folder) || !filesystem::is_directory(local_seed_folder)) {
        return;
    }

    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path archive_dir =
        filesystem::path("archive") / safe_label / ("round_" + to_string(round));
    const filesystem::path manifest_path = archive_dir / "manifest.txt";

    if (filesystem::exists(archive_dir)) {
        filesystem::remove_all(archive_dir);
    }
    filesystem::create_directories(archive_dir);

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(local_seed_folder)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    ofstream manifest(manifest_path);
    if (!manifest.is_open()) {
        std::cout << "[LEGION] warning: failed to open archive manifest for "
                  << fuzzer_label << " round " << round << endl;
        return;
    }

    size_t archived = 0;
    size_t skipped_initial = 0;
    for (const auto& seed_path : seed_files) {
        const string fingerprint = eval_file_fingerprint(seed_path);
        if (round_initial_fingerprints.count(fingerprint) > 0) {
            skipped_initial++;
            continue;
        }

        const filesystem::path archived_path = archive_dir / seed_path.filename();
        std::error_code ec;
        filesystem::copy_file(seed_path,
                              archived_path,
                              filesystem::copy_options::overwrite_existing,
                              ec);
        if (ec) {
            std::cout << "[LEGION] warning: failed to archive seed "
                      << seed_path << " for " << fuzzer_label
                      << ": " << ec.message() << endl;
            continue;
        }

        manifest << seed_path.filename().string() << " " << fingerprint << endl;
        archived++;
    }

    std::cout << "[LEGION] archived " << archived
              << " round-new seeds for " << fuzzer_label
              << " under " << archive_dir.string()
              << " (skipped " << skipped_initial << " round-start seeds)" << endl;
}

struct crash_seed_entry_t {
    filesystem::path source_path;
    string worker_label;
};

static bool is_valid_crash_seed_file(const filesystem::path& crash_path) {
    if (!filesystem::is_regular_file(crash_path)) {
        return false;
    }
    string name = crash_path.filename().string();
    if (name.empty()) {
        return false;
    }
    if (name == "README" || name == "README.txt" || name[0] == '.') {
        return false;
    }
    return true;
}

static bool is_honggfuzz_crash_seed_file(const filesystem::path& crash_path) {
    if (!is_valid_crash_seed_file(crash_path)) {
        return false;
    }
    const string name = crash_path.filename().string();
    static const vector<string> signal_prefixes = {
        "SIGSEGV.", "SIGABRT.", "SIGILL.", "SIGFPE.", "SIGBUS.", "SIGTRAP."
    };
    for (const auto& prefix : signal_prefixes) {
        if (name.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

static void collect_afl_like_crash_entries(const filesystem::path& output_root,
                                           vector<crash_seed_entry_t>& entries) {
    if (!filesystem::exists(output_root) || !filesystem::is_directory(output_root)) {
        return;
    }

    for (const auto& worker_dir : filesystem::directory_iterator(output_root)) {
        if (!filesystem::is_directory(worker_dir.path())) {
            continue;
        }

        const filesystem::path crashes_dir = worker_dir.path() / "crashes";
        if (!filesystem::exists(crashes_dir) || !filesystem::is_directory(crashes_dir)) {
            continue;
        }

        for (const auto& crash_entry : filesystem::directory_iterator(crashes_dir)) {
            if (!is_valid_crash_seed_file(crash_entry.path())) {
                continue;
            }
            entries.push_back({crash_entry.path(), worker_dir.path().filename().string()});
        }
    }
}

static void collect_libfuzzer_crash_entries(const filesystem::path& output_root,
                                            vector<crash_seed_entry_t>& entries) {
    if (!filesystem::exists(output_root) || !filesystem::is_directory(output_root)) {
        return;
    }

    for (const auto& crash_entry : filesystem::directory_iterator(output_root)) {
        if (!filesystem::is_regular_file(crash_entry.path())) {
            continue;
        }
        const string filename = crash_entry.path().filename().string();
        if (filename.rfind("crash", 0) != 0) {
            continue;
        }
        entries.push_back({crash_entry.path(), "output"});
    }
}

static void collect_honggfuzz_crash_entries(const filesystem::path& run_root,
                                            vector<crash_seed_entry_t>& entries) {
    if (!filesystem::exists(run_root) || !filesystem::is_directory(run_root)) {
        return;
    }

    for (const auto& crash_entry : filesystem::directory_iterator(run_root)) {
        if (is_honggfuzz_crash_seed_file(crash_entry.path())) {
            entries.push_back({crash_entry.path(), "workspace"});
        }
    }

    const filesystem::path output_dir = run_root / "output";
    if (!filesystem::exists(output_dir) || !filesystem::is_directory(output_dir)) {
        return;
    }
    for (const auto& crash_entry : filesystem::directory_iterator(output_dir)) {
        if (is_honggfuzz_crash_seed_file(crash_entry.path())) {
            entries.push_back({crash_entry.path(), "output"});
        }
    }
}

static vector<crash_seed_entry_t> collect_round_crash_entries(const string& fuzzer_label) {
    vector<crash_seed_entry_t> entries;
    if (fuzzer_label == "AFL++") {
        collect_afl_like_crash_entries(filesystem::path("run_aflpp") / "output", entries);
    } else if (fuzzer_label == "AFL") {
        collect_afl_like_crash_entries(filesystem::path("run_afl") / "output", entries);
    } else if (fuzzer_label == "AFLFast") {
        collect_afl_like_crash_entries(filesystem::path("run_aflfast") / "output", entries);
    } else if (fuzzer_label == "FairFuzz") {
        collect_afl_like_crash_entries(filesystem::path("run_fairfuzz") / "output", entries);
    } else if (fuzzer_label == "Angora") {
        collect_afl_like_crash_entries(filesystem::path("run_angora") / "output", entries);
    } else if (fuzzer_label == "QSYM") {
        collect_afl_like_crash_entries(filesystem::path("run_qsym") / "output", entries);
    } else if (fuzzer_label == "LibFuzzer") {
        collect_libfuzzer_crash_entries(filesystem::path("run_lib") / "output" / "crashes", entries);
    } else if (fuzzer_label == "HonggFuzz") {
        collect_honggfuzz_crash_entries("run_hongg", entries);
    }

    sort(entries.begin(), entries.end(), [](const crash_seed_entry_t& lhs,
                                            const crash_seed_entry_t& rhs) {
        if (lhs.worker_label != rhs.worker_label) {
            return lhs.worker_label < rhs.worker_label;
        }
        return lhs.source_path.string() < rhs.source_path.string();
    });
    return entries;
}

static void archive_round_crash_seeds(const string& fuzzer_label, size_t round) {
    vector<crash_seed_entry_t> entries = collect_round_crash_entries(fuzzer_label);
    if (entries.empty()) {
        return;
    }

    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path archive_dir =
        filesystem::path("saved_crashes") / safe_label / ("round_" + to_string(round));
    const filesystem::path manifest_path = archive_dir / "manifest.txt";

    if (filesystem::exists(archive_dir)) {
        filesystem::remove_all(archive_dir);
    }
    filesystem::create_directories(archive_dir);

    ofstream manifest(manifest_path);
    if (!manifest.is_open()) {
        std::cout << "[LEGION] warning: failed to open crash manifest for "
                  << fuzzer_label << " round " << round << endl;
        return;
    }

    size_t archived = 0;
    for (const auto& crash_entry : entries) {
        const string worker_label = sanitize_eval_label(crash_entry.worker_label);
        const filesystem::path worker_dir = archive_dir / worker_label;
        filesystem::create_directories(worker_dir);

        const filesystem::path dest_path = worker_dir / crash_entry.source_path.filename();
        std::error_code ec;
        filesystem::copy_file(crash_entry.source_path,
                              dest_path,
                              filesystem::copy_options::overwrite_existing,
                              ec);
        if (ec) {
            std::cout << "[LEGION] warning: failed to save crash seed "
                      << crash_entry.source_path << " for " << fuzzer_label
                      << ": " << ec.message() << endl;
            continue;
        }

        manifest << worker_label << "/"
                 << crash_entry.source_path.filename().string()
                 << " " << eval_file_fingerprint(crash_entry.source_path)
                 << " " << crash_entry.source_path.string() << endl;
        archived++;
    }

    std::cout << "[LEGION] archived " << archived
              << " crash seeds for " << fuzzer_label
              << " under " << archive_dir.string() << endl;
}

struct sync_seed_features_t {
    unordered_set<unsigned long> edges;
    unordered_set<uint32_t> paths;
    string fingerprint;
};

static bool sync_metric_targets_empty(const sync_metric_targets_t& targets) {
    return targets.c0_edges.empty() &&
           targets.c1_paths.empty() &&
           targets.c2_crashes.empty() &&
           targets.c3_deep_edges.empty() &&
           targets.c4_low_freq_edges.empty();
}

static size_t sync_metric_targets_count(const sync_metric_targets_t& targets) {
    return targets.c0_edges.size() +
           targets.c1_paths.size() +
           targets.c2_crashes.size() +
           targets.c3_deep_edges.size() +
           targets.c4_low_freq_edges.size();
}

static bool parse_sync_seed_report(const filesystem::path& report_path,
                                   sync_seed_features_t& features) {
    ifstream in(report_path);
    if (!in.is_open()) {
        return false;
    }

    enum report_section_t {
        REPORT_NONE,
        REPORT_EDGE,
        REPORT_PATH
    };

    report_section_t section = REPORT_NONE;
    string line;
    while (getline(in, line)) {
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
            } else {
                section = REPORT_NONE;
            }
            continue;
        }

        if (section == REPORT_EDGE) {
            unsigned long id = 0;
            unsigned long count = 0;
            if (sscanf(line.c_str(), "%lu %lu", &id, &count) == 2 && count > 0) {
                features.edges.insert(id);
            }
            continue;
        }

        if (section == REPORT_PATH) {
            unsigned long hash = 0;
            unsigned long count = 0;
            if (sscanf(line.c_str(), "%lu %lu", &hash, &count) == 2 && count > 0) {
                features.paths.insert(static_cast<uint32_t>(hash));
            }
        }
    }

    return true;
}

static bool load_cached_sync_seed_features(const string& fuzzer_label,
                                           size_t round,
                                           sync_seed_features_t& features) {
    const filesystem::path cache_path =
        eval_seed_report_cache_path(fuzzer_label, round, features.fingerprint);
    if (!filesystem::exists(cache_path) || !filesystem::is_regular_file(cache_path)) {
        return false;
    }
    return parse_sync_seed_report(cache_path, features);
}

static bool collect_sync_seed_features_via_replay(const filesystem::path& seed_path,
                                                  const filesystem::path& temp_root,
                                                  size_t index,
                                                  sync_seed_features_t& features) {
    filesystem::path single_seed_dir = temp_root / ("seed_" + to_string(index));
    filesystem::create_directories(single_seed_dir);
    filesystem::path staged_seed = single_seed_dir / seed_path.filename();

    std::error_code ec;
    filesystem::create_hard_link(seed_path, staged_seed, ec);
    if (ec) {
        ec.clear();
        filesystem::copy_file(seed_path,
                              staged_seed,
                              filesystem::copy_options::overwrite_existing,
                              ec);
        if (ec) {
            std::cout << "[LEGION] warning: failed to stage sync candidate "
                      << seed_path << " for metric filtering" << endl;
            filesystem::remove_all(single_seed_dir);
            return false;
        }
    }

    filesystem::path report_path = temp_root / ("seed_" + to_string(index) + ".report");
    string command = "build/instrumentapp " + single_seed_dir.string() + " " + report_path.string();
    if (eval_seed_timeout > 0) {
        command += " --seed-timeout " + to_string(eval_seed_timeout);
    }
    run_command(command);
    bool parsed = parse_sync_seed_report(report_path, features);

    filesystem::remove(single_seed_dir / seed_path.filename());
    filesystem::remove_all(single_seed_dir);
    filesystem::remove(report_path);
    return parsed;
}

static bool sync_seed_has_metric_contribution(const sync_seed_features_t& features,
                                              const sync_metric_targets_t& remaining) {
    if (remaining.c2_crashes.count(features.fingerprint) > 0) {
        return true;
    }

    for (unsigned long edge_id : features.edges) {
        if (remaining.c0_edges.count(edge_id) > 0 ||
            remaining.c3_deep_edges.count(edge_id) > 0 ||
            remaining.c4_low_freq_edges.count(edge_id) > 0) {
            return true;
        }
    }

    for (uint32_t path_hash : features.paths) {
        if (remaining.c1_paths.count(path_hash) > 0) {
            return true;
        }
    }

    return false;
}

static void consume_sync_metric_targets(const sync_seed_features_t& features,
                                        sync_metric_targets_t& remaining) {
    remaining.c2_crashes.erase(features.fingerprint);

    for (unsigned long edge_id : features.edges) {
        remaining.c0_edges.erase(edge_id);
        remaining.c3_deep_edges.erase(edge_id);
        remaining.c4_low_freq_edges.erase(edge_id);
    }

    for (uint32_t path_hash : features.paths) {
        remaining.c1_paths.erase(path_hash);
    }
}

static filesystem::path staged_round_crash_dir(const string& fuzzer_label, size_t round) {
    return filesystem::path(".round_crashes") /
           (sanitize_eval_label(fuzzer_label) + "_" + to_string(round));
}

static void ensure_clean_directory(const filesystem::path& dir_path) {
    if (filesystem::exists(dir_path)) {
        filesystem::remove_all(dir_path);
    }
    filesystem::create_directories(dir_path);
}

static void merge_seed_folder_into_accum(const string& source_folder, const string& accum_folder) {
    filesystem::path source_path = source_folder;
    filesystem::path accum_path = accum_folder;
    filesystem::create_directories(accum_path);
    if (!filesystem::exists(source_path) || !filesystem::is_directory(source_path)) {
        return;
    }

    unordered_set<string> existing_fingerprints;
    for (const auto& entry : filesystem::directory_iterator(accum_path)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        existing_fingerprints.insert(eval_file_fingerprint(entry.path()));
    }

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(source_path)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    size_t merged = 0;
    size_t skipped = 0;
    for (const auto& seed_path : seed_files) {
        const string fingerprint = eval_file_fingerprint(seed_path);
        if (!existing_fingerprints.insert(fingerprint).second) {
            skipped++;
            continue;
        }

        filesystem::path target_path = accum_path / fingerprint;
        if (filesystem::exists(target_path)) {
            target_path = accum_path / (fingerprint + "_" + seed_path.filename().string());
        }

        std::error_code ec;
        filesystem::copy_file(seed_path,
                              target_path,
                              filesystem::copy_options::overwrite_existing,
                              ec);
        if (ec) {
            std::cout << "[LEGION] warning: failed to merge seed " << seed_path
                      << " into " << accum_folder << ": " << ec.message() << endl;
            continue;
        }
        merged++;
    }

    if (merged > 0 || skipped > 0) {
        std::cout << "[LEGION] merged live seeds from " << source_folder
                  << " into " << accum_folder
                  << " (new=" << merged << ", duplicate=" << skipped << ")" << endl;
    }
}

static void stage_current_round_crashes(const string& fuzzer_label, size_t round) {
    vector<crash_seed_entry_t> entries = collect_round_crash_entries(fuzzer_label);
    if (entries.empty()) {
        return;
    }

    const filesystem::path stage_dir = staged_round_crash_dir(fuzzer_label, round);
    filesystem::create_directories(stage_dir);
    const filesystem::path manifest_path = stage_dir / "manifest.txt";

    unordered_set<string> seen_fingerprints;
    load_seen_fingerprints(manifest_path, seen_fingerprints);

    vector<string> appended_fingerprints;
    size_t staged = 0;
    for (const auto& entry : entries) {
        const string fingerprint = eval_file_fingerprint(entry.source_path);
        if (!seen_fingerprints.insert(fingerprint).second) {
            continue;
        }

        filesystem::path staged_path = stage_dir / fingerprint;
        if (filesystem::exists(staged_path)) {
            staged_path = stage_dir / (fingerprint + "_" + entry.source_path.filename().string());
        }

        std::error_code ec;
        filesystem::copy_file(entry.source_path,
                              staged_path,
                              filesystem::copy_options::overwrite_existing,
                              ec);
        if (ec) {
            std::cout << "[LEGION] warning: failed to stage crash seed "
                      << entry.source_path << ": " << ec.message() << endl;
            continue;
        }

        appended_fingerprints.push_back(fingerprint);
        staged++;
    }

    if (!append_seen_fingerprints(manifest_path, appended_fingerprints)) {
        std::cout << "[LEGION] warning: failed to update crash manifest for "
                  << fuzzer_label << endl;
    }

    if (staged > 0) {
        std::cout << "[LEGION] staged " << staged << " unique crash seeds for "
                  << fuzzer_label << " in round " << round << endl;
    }
}

static void export_staged_round_crashes(const string& fuzzer_label, size_t round) {
    const filesystem::path stage_dir = staged_round_crash_dir(fuzzer_label, round);
    if (!filesystem::exists(stage_dir) || !filesystem::is_directory(stage_dir)) {
        return;
    }

    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path archive_dir =
        filesystem::path("saved_crashes") / safe_label / ("round_" + to_string(round));
    const filesystem::path manifest_path = archive_dir / "manifest.txt";

    if (filesystem::exists(archive_dir)) {
        filesystem::remove_all(archive_dir);
    }
    filesystem::create_directories(archive_dir);

    ofstream manifest(manifest_path);
    if (!manifest.is_open()) {
        std::cout << "[LEGION] warning: failed to open staged crash manifest for "
                  << fuzzer_label << " round " << round << endl;
        return;
    }

    size_t archived = 0;
    for (const auto& entry : filesystem::directory_iterator(stage_dir)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        if (entry.path().filename() == "manifest.txt") {
            continue;
        }

        const string fingerprint = eval_file_fingerprint(entry.path());
        const filesystem::path archived_path = archive_dir / entry.path().filename();
        std::error_code ec;
        filesystem::copy_file(entry.path(),
                              archived_path,
                              filesystem::copy_options::overwrite_existing,
                              ec);
        if (ec) {
            std::cout << "[LEGION] warning: failed to archive staged crash "
                      << entry.path() << ": " << ec.message() << endl;
            continue;
        }
        manifest << entry.path().filename().string() << " " << fingerprint << endl;
        archived++;
    }

    if (archived > 0) {
        std::cout << "[LEGION] archived " << archived
                  << " crash seeds for " << fuzzer_label
                  << " under " << archive_dir.string() << endl;
    }
}

static filesystem::path prepare_fuzzer_initial_snapshot(const string& label,
                                                        const string& accum_seed_folder,
                                                        const string& group_mode,
                                                        uint32_t worker_index) {
    const filesystem::path snapshot_dir =
        filesystem::path(FUZZER_INPUT_SNAPSHOT_ROOT) /
        (sanitize_eval_label(label) + "_" + accum_seed_folder + "_" +
         group_mode + "_" + to_string(worker_index));
    ensure_clean_directory(snapshot_dir);

    const string source_pool =
        (do_minimize && filesystem::exists(GLOBAL_CMIN_INPUT_POOL_NAME))
            ? string(GLOBAL_CMIN_INPUT_POOL_NAME)
            : string(GLOBAL_POOL_NAME);
    copy_immediate_files_to_dir(source_pool, snapshot_dir);
    copy_immediate_files_to_dir(accum_seed_folder, snapshot_dir);

    std::cout << "[LEGION] prepared private initial snapshot for " << label
              << " at " << filesystem::absolute(snapshot_dir).string() << endl;
    return filesystem::absolute(snapshot_dir);
}

static string with_private_initial_env(const string& command,
                                       const filesystem::path& snapshot_dir) {
    return "LEGION_INITIAL_DIR=" + shell_quote(snapshot_dir.string()) + " " + command;
}

static bool supports_runtime_append(const string& label) {
    return label == "AFL++" ||
           label == "AFL" ||
           label == "AFLFast" ||
           label == "FairFuzz" ||
           label == "QSYM" ||
           label == "LibFuzzer" ||
           label == "Angora" ||
           label == "Radamsa";
}

static bool uses_fresh_round_process(const string& label) {
    return label == "Radamsa";
}

static bool uses_autofz_afl_process_pool(const string& label) {
    return label == "AFL++" ||
           label == "AFL" ||
           label == "AFLFast" ||
           label == "FairFuzz";
}

static bool uses_autofz_qsym_process_pool(const string& label) {
    return label == "QSYM";
}

static bool uses_autofz_indexed_append(const string& label) {
    return uses_autofz_afl_process_pool(label) ||
           uses_autofz_qsym_process_pool(label);
}

static uint32_t runtime_resource_units_for_fuzzer(const string& label,
                                                  uint32_t accounting_units) {
    if (uses_autofz_qsym_process_pool(label) && accounting_units > 0) {
        return accounting_units + 1;
    }
    return accounting_units;
}

static bool uses_direct_persistent_worker(const string& label) {
    return uses_autofz_afl_process_pool(label) ||
           uses_autofz_qsym_process_pool(label) ||
           label == "LibFuzzer";
}

static filesystem::path runtime_dir_for_label(const string& label) {
    if (label == "AFL++") {
        return "run_aflpp";
    }
    if (label == "AFL") {
        return "run_afl";
    }
    if (label == "AFLFast") {
        return "run_aflfast";
    }
    if (label == "FairFuzz") {
        return "run_fairfuzz";
    }
    if (label == "QSYM") {
        return "run_qsym";
    }
    if (label == "LibFuzzer") {
        return "run_lib";
    }
    if (label == "Radamsa") {
        return "run_radamsa";
    }
    return "";
}

static bool directory_has_regular_file(const filesystem::path& dir_path) {
    if (!filesystem::exists(dir_path) || !filesystem::is_directory(dir_path)) {
        return false;
    }
    for (const auto& entry : filesystem::directory_iterator(dir_path)) {
        if (filesystem::is_regular_file(entry.path())) {
            return true;
        }
    }
    return false;
}

static bool wait_for_file_path(const filesystem::path& path, uint32_t timeout_seconds) {
    for (uint32_t waited = 0; waited < timeout_seconds; ++waited) {
        if (filesystem::exists(path) && filesystem::is_regular_file(path)) {
            return true;
        }
        sleep(1);
    }
    return filesystem::exists(path) && filesystem::is_regular_file(path);
}

static bool prepare_direct_runtime_dir(const string& label,
                                       const filesystem::path& snapshot_dir,
                                       bool clean_runtime) {
    const filesystem::path run_dir = runtime_dir_for_label(label);
    if (run_dir.empty()) {
        return false;
    }
    if (clean_runtime) {
        ensure_clean_directory(run_dir);
    }
    filesystem::create_directories(run_dir / "input");
    filesystem::create_directories(run_dir / "output");

    if (label == "LibFuzzer") {
        filesystem::create_directories(run_dir / "output" / "queue");
        filesystem::create_directories(run_dir / "output" / "crashes");
        filesystem::create_directories(run_dir / "output" / "autofz" / "queue");
    }

    copy_immediate_files_to_dir(snapshot_dir, run_dir / "input");
    if (!directory_has_regular_file(run_dir / "input")) {
        std::cout << "[LEGION] no initial seeds available for "
                  << label << ", skip starting persistent worker" << endl;
        return false;
    }
    return true;
}

static string afl_like_tool_env_prefix(const string& label) {
    string prefix =
        "export TOOLS_ROOT=\"${TOOLS_ROOT:-/FuzzingTools}\"; "
        "if [[ ! -d \"$TOOLS_ROOT\" && -d /home/threedean/FuzzingTools ]]; then "
        "TOOLS_ROOT=/home/threedean/FuzzingTools; fi; "
        "export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; "
        "export AFL_SKIP_CPUFREQ=1; ";
    if (label == "AFL++") {
        prefix +=
            "export AFLPP_BIN=\"${AFLPP_BIN:-$TOOLS_ROOT/AFLplusplus}\"; "
            "export AFL_PATH=\"$AFLPP_BIN\"; "
            "export AFL_IGNORE_UNKNOWN_ENVS=1; "
            "export AFLPP_LLVM_LIBDIR=\"${AFLPP_LLVM_LIBDIR:-/clang+llvm/lib}\"; "
            "export LD_LIBRARY_PATH=\"$AFLPP_LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"; ";
    } else if (label == "AFL") {
        prefix += "export AFL_BIN=\"${AFL_BIN:-$TOOLS_ROOT/AFL}\"; ";
    } else if (label == "AFLFast") {
        prefix += "export AFLFAST_BIN=\"${AFLFAST_BIN:-$TOOLS_ROOT/AFLFast}\"; ";
    } else if (label == "FairFuzz") {
        prefix += "export FAIRFUZZ_BIN=\"${FAIRFUZZ_BIN:-$TOOLS_ROOT/FairFuzz}\"; ";
    }
    return prefix;
}

static string afl_like_runner_expr(const string& label) {
    if (label == "AFL++") {
        return "\"$AFLPP_BIN/afl-fuzz\"";
    }
    if (label == "AFL") {
        return "\"$AFL_BIN/afl-fuzz\"";
    }
    if (label == "AFLFast") {
        return "\"$AFLFAST_BIN/afl-fuzz\"";
    }
    if (label == "FairFuzz") {
        return "\"$FAIRFUZZ_BIN/afl-fuzz\"";
    }
    return "";
}

static string afl_like_target_for_label(const string& label) {
    if (label == "AFL++") {
        return "../build/aflppapp";
    }
    if (label == "AFL") {
        return "../build/aflapp";
    }
    if (label == "AFLFast") {
        return "../build/aflfastapp";
    }
    if (label == "FairFuzz") {
        return "../build/fairfuzzapp";
    }
    return "";
}

static string build_direct_afl_worker_command(const string& label,
                                              uint32_t worker_index,
                                              bool master) {
    const filesystem::path run_dir = runtime_dir_for_label(label);
    const string runner = afl_like_runner_expr(label);
    const string target = afl_like_target_for_label(label);
    const string role = master ? "-M fuzzer0" : "-S fuzzer" + to_string(worker_index);
    const string dict = use_dictionary ? " -x ../dict.dict" : "";

    string command = afl_like_tool_env_prefix(label);
    command += "cd " + shell_quote(run_dir.string()) + " && exec " + runner +
               " -m none -t \"${LEGION_AFL_TIMEOUT:-1000+}\""
               " -i input -o output " + role + dict +
               " -- " + shell_quote(target);
    return command;
}

static string build_direct_qsym_afl_command(uint32_t worker_index, bool master) {
    const string role = master ? "-M afl-master" : "-S afl-slave" + to_string(worker_index);
    const string dict = use_dictionary ? " -x ../dict.dict" : "";
    string command =
        "export TOOLS_ROOT=\"${TOOLS_ROOT:-/FuzzingTools}\"; "
        "if [[ ! -d \"$TOOLS_ROOT\" && -d /home/threedean/FuzzingTools ]]; then "
        "TOOLS_ROOT=/home/threedean/FuzzingTools; fi; "
        "export AFL_BIN=\"${AFL_BIN:-$TOOLS_ROOT/AFL}\"; "
        "export AFLPP_BIN=\"${AFLPP_BIN:-$TOOLS_ROOT/AFLplusplus}\"; "
        "export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; "
        "export AFL_SKIP_CPUFREQ=1; "
        "cd run_qsym && "
        "afl_runner=\"$AFL_BIN/afl-fuzz\"; "
        "afl_target=\"../build/aflapp\"; "
        "if [[ ! -x \"$afl_runner\" && -x \"$AFLPP_BIN/afl-fuzz\" ]]; then "
        "afl_runner=\"$AFLPP_BIN/afl-fuzz\"; fi; "
        "if [[ ! -x \"$afl_target\" && -x ../build/aflppapp ]]; then "
        "afl_target=\"../build/aflppapp\"; fi; "
        "exec \"$afl_runner\" -m none "
        "-t \"${LEGION_AFL_TIMEOUT:-1000+}\" -i input -o output " +
        role + dict + " -- \"$afl_target\"";
    return command;
}

static string build_direct_qsym_se_command() {
    string command =
        "export TOOLS_ROOT=\"${TOOLS_ROOT:-/FuzzingTools}\"; "
        "if [[ ! -d \"$TOOLS_ROOT\" && -d /home/threedean/FuzzingTools ]]; then "
        "TOOLS_ROOT=/home/threedean/FuzzingTools; fi; "
        "export QSYM_BIN=\"${QSYM_BIN:-$TOOLS_ROOT/QSYM}\"; "
        "for candidate in \"$QSYM_BIN\" \"$TOOLS_ROOT/QSYM-real\" "
        "\"/Legion/.cache/qsym-sslab-gatech\" "
        "\"/data/yukaizhao/Legion/.cache/qsym-sslab-gatech\"; do "
        "if [[ -f \"$candidate/setup.py\" && -f \"$candidate/bin/run_qsym_afl.py\" ]]; then "
        "QSYM_BIN=\"$candidate\"; break; fi; done; "
        "export QSYM_PIN_INJECTION=\"${QSYM_PIN_INJECTION:-child}\"; "
        "cd run_qsym && "
        "afl_target=\"../build/aflapp\"; "
        "if [[ ! -x \"$afl_target\" && -x ../build/aflppapp ]]; then "
        "afl_target=\"../build/aflppapp\"; fi; "
        "exec env PYTHONPATH=\"$QSYM_BIN:${PYTHONPATH:-}\" "
        "python2 \"$QSYM_BIN/bin/run_qsym_afl.py\" "
        "-a afl-master -o output -n qsym -b \"$afl_target\" -- ../build/qsymapp @@";
    return command;
}

static string build_direct_libfuzzer_worker_command() {
    const string dict = use_dictionary ? " -dict=../dict.dict" : "";
    return "cd run_lib && exec ../build/libapp -fork=1 -ignore_crashes=1 "
           "-artifact_prefix=./output/crashes/" + dict +
           " ./output/queue/ ./input/ ./output/autofz/";
}

static bool should_snapshot_afl_like_output_dir(const filesystem::path& path) {
    const string name = path.filename().string();
    if (name == "legion_sync" || name.empty() || name[0] == '.') {
        return false;
    }
    return name.rfind("fuzzer", 0) == 0 ||
           name.rfind("afl-master", 0) == 0 ||
           name.rfind("afl-slave", 0) == 0 ||
           name.rfind("qsym", 0) == 0;
}

static void snapshot_runtime_outputs_for_label(const string& fuzzer_label,
                                               const filesystem::path& dst_dir) {
    filesystem::create_directories(dst_dir);

    if (fuzzer_label == "AFL++") {
        const filesystem::path output_dir = filesystem::path("run_aflpp") / "output";
        if (filesystem::exists(output_dir) && filesystem::is_directory(output_dir)) {
            for (const auto& entry : filesystem::directory_iterator(output_dir)) {
                if (filesystem::is_directory(entry.path()) &&
                    should_snapshot_afl_like_output_dir(entry.path())) {
                    copy_immediate_files_to_dir(entry.path() / "queue", dst_dir);
                }
            }
        }
        return;
    }

    if (fuzzer_label == "AFL") {
        const filesystem::path output_dir = filesystem::path("run_afl") / "output";
        if (filesystem::exists(output_dir) && filesystem::is_directory(output_dir)) {
            for (const auto& entry : filesystem::directory_iterator(output_dir)) {
                if (filesystem::is_directory(entry.path()) &&
                    should_snapshot_afl_like_output_dir(entry.path())) {
                    copy_immediate_files_to_dir(entry.path() / "queue", dst_dir);
                }
            }
        }
        return;
    }

    if (fuzzer_label == "AFLFast") {
        const filesystem::path output_dir = filesystem::path("run_aflfast") / "output";
        if (filesystem::exists(output_dir) && filesystem::is_directory(output_dir)) {
            for (const auto& entry : filesystem::directory_iterator(output_dir)) {
                if (filesystem::is_directory(entry.path()) &&
                    should_snapshot_afl_like_output_dir(entry.path())) {
                    copy_immediate_files_to_dir(entry.path() / "queue", dst_dir);
                }
            }
        }
        return;
    }

    if (fuzzer_label == "FairFuzz") {
        const filesystem::path output_dir = filesystem::path("run_fairfuzz") / "output";
        if (filesystem::exists(output_dir) && filesystem::is_directory(output_dir)) {
            for (const auto& entry : filesystem::directory_iterator(output_dir)) {
                if (filesystem::is_directory(entry.path()) &&
                    should_snapshot_afl_like_output_dir(entry.path())) {
                    copy_immediate_files_to_dir(entry.path() / "queue", dst_dir);
                }
            }
        }
        return;
    }

    if (fuzzer_label == "QSYM") {
        const filesystem::path output_dir = filesystem::path("run_qsym") / "output";
        if (filesystem::exists(output_dir) && filesystem::is_directory(output_dir)) {
            for (const auto& entry : filesystem::directory_iterator(output_dir)) {
                if (filesystem::is_directory(entry.path()) &&
                    should_snapshot_afl_like_output_dir(entry.path())) {
                    copy_immediate_files_to_dir(entry.path() / "queue", dst_dir);
                }
            }
        }
        return;
    }

    if (fuzzer_label == "Angora") {
        const filesystem::path output_dir = filesystem::path("run_angora") / "output";
        copy_immediate_files_to_dir(output_dir / "queue", dst_dir);
        if (filesystem::exists(output_dir) && filesystem::is_directory(output_dir)) {
            for (const auto& entry : filesystem::directory_iterator(output_dir)) {
                if (filesystem::is_directory(entry.path()) &&
                    should_snapshot_afl_like_output_dir(entry.path())) {
                    copy_immediate_files_to_dir(entry.path() / "queue", dst_dir);
                }
            }
        }
        return;
    }

    if (fuzzer_label == "LibFuzzer") {
        copy_immediate_files_to_dir(filesystem::path("run_lib") / "output" / "queue", dst_dir);
        return;
    }

    if (fuzzer_label == "Radamsa") {
        copy_immediate_files_to_dir(filesystem::path("run_radamsa") / "output", dst_dir);
        return;
    }

    if (fuzzer_label == "HonggFuzz") {
        copy_recursive_files_to_dir(filesystem::path("run_hongg") / "output", dst_dir);
        return;
    }
}

static string build_run_command(const fuzzer_t& fuzzer,
                                uint32_t execution_time,
                                uint32_t scheduled_units,
                                const string& outfolder) {
    string fuzz_command = fuzzer.script + " run " + to_string(execution_time) +
                          " " + to_string(scheduled_units) + " " + outfolder;
    if (use_dictionary) {
        fuzz_command += " -d";
    }
    return fuzz_command;
}

static string build_append_command(const fuzzer_t& fuzzer,
                                   uint32_t execution_time,
                                   uint32_t additional_units,
                                   const string& outfolder) {
    string fuzz_command = fuzzer.script + " append " + to_string(execution_time) +
                          " " + to_string(additional_units) + " " + outfolder;
    if (use_dictionary) {
        fuzz_command += " -d";
    }
    return fuzz_command;
}

static pid_t start_command_process_group(const string& command) {
    pid_t pid = fork();
    if (pid < 0) {
        std::cout << "[LEGION] error: fork failed for command: " << command << endl;
        return -1;
    }

    if (pid == 0) {
        if (setsid() < 0) {
            _exit(127);
        }
        execl("/bin/bash", "bash", "-lc", command.c_str(), (char*)nullptr);
        _exit(127);
    }

    return pid;
}

static bool read_proc_ppid(pid_t pid, pid_t& ppid) {
    ifstream in("/proc/" + to_string(pid) + "/status");
    if (!in.is_open()) {
        return false;
    }

    string line;
    while (getline(in, line)) {
        if (line.rfind("PPid:", 0) != 0) {
            continue;
        }
        istringstream iss(line.substr(5));
        iss >> ppid;
        return !iss.fail();
    }
    return false;
}

static bool is_pid_directory_name(const string& name) {
    if (name.empty()) {
        return false;
    }
    for (unsigned char ch : name) {
        if (!isdigit(ch)) {
            return false;
        }
    }
    return true;
}

static bool process_exists(pid_t pid) {
    if (pid <= 0) {
        return false;
    }
    if (kill(pid, 0) == 0) {
        return true;
    }
    return errno == EPERM;
}

static void signal_pid_ignore_missing(pid_t pid, int signal_number);

static string read_proc_cmdline(pid_t pid) {
    ifstream in("/proc/" + to_string(pid) + "/cmdline", ios::binary);
    if (!in.is_open()) {
        return "";
    }

    string cmdline((istreambuf_iterator<char>(in)),
                   istreambuf_iterator<char>());
    for (char& ch : cmdline) {
        if (ch == '\0') {
            ch = ' ';
        }
    }
    return trim_copy(cmdline);
}

static string normalize_proc_path_string(string path_text) {
    static const string deleted_suffix = " (deleted)";
    if (path_text.size() >= deleted_suffix.size() &&
        path_text.compare(path_text.size() - deleted_suffix.size(),
                          deleted_suffix.size(),
                          deleted_suffix) == 0) {
        path_text.resize(path_text.size() - deleted_suffix.size());
    }
    return path_text;
}

static string read_proc_cwd(pid_t pid) {
    std::error_code ec;
    filesystem::path cwd_path =
        filesystem::read_symlink("/proc/" + to_string(pid) + "/cwd", ec);
    if (ec) {
        return "";
    }
    return normalize_proc_path_string(cwd_path.string());
}

static bool path_is_same_or_descendant(const string& candidate,
                                       const string& root) {
    if (candidate.empty() || root.empty()) {
        return false;
    }
    if (candidate == root) {
        return true;
    }
    if (candidate.size() <= root.size() || candidate.compare(0, root.size(), root) != 0) {
        return false;
    }
    return root.back() == '/' || candidate[root.size()] == '/';
}

static vector<string> runtime_dirs_for_label(const string& label) {
    if (label == "AFL++") {
        return {"run_aflpp"};
    }
    if (label == "AFL") {
        return {"run_afl"};
    }
    if (label == "AFLFast") {
        return {"run_aflfast"};
    }
    if (label == "FairFuzz") {
        return {"run_fairfuzz"};
    }
    if (label == "QSYM") {
        return {"run_qsym"};
    }
    if (label == "LibFuzzer") {
        return {"run_lib"};
    }
    if (label == "Radamsa") {
        return {"run_radamsa"};
    }
    if (label == "Angora") {
        return {"run_angora"};
    }
    if (label == "HonggFuzz") {
        return {"run_hongg"};
    }
    return {};
}

static string script_basename_for_label(const string& label) {
    if (label == "AFL++") {
        return "AFLPP.sh";
    }
    if (label == "AFL") {
        return "AFL.sh";
    }
    if (label == "AFLFast") {
        return "AFLFast.sh";
    }
    if (label == "FairFuzz") {
        return "FairFuzz.sh";
    }
    if (label == "QSYM") {
        return "QSYM.sh";
    }
    if (label == "LibFuzzer") {
        return "LIBFUZZER.sh";
    }
    if (label == "Radamsa") {
        return "RADAMSA.sh";
    }
    if (label == "Angora") {
        return "Angora.sh";
    }
    if (label == "HonggFuzz") {
        return "HONGG.sh";
    }
    return "";
}

static void collect_label_runtime_processes(const string& label, set<pid_t>& matches) {
    std::error_code ec;
    const filesystem::path run_root_path = filesystem::current_path(ec);
    if (ec) {
        return;
    }
    const string run_root = normalize_proc_path_string(run_root_path.string());
    const vector<string> runtime_dirs = runtime_dirs_for_label(label);
    const string script_name = script_basename_for_label(label);
    const pid_t self_pid = getpid();

    for (const auto& entry : filesystem::directory_iterator("/proc", ec)) {
        if (ec) {
            break;
        }
        const string name = entry.path().filename().string();
        if (!is_pid_directory_name(name)) {
            continue;
        }

        pid_t pid = static_cast<pid_t>(stol(name));
        if (pid <= 0 || pid == self_pid || !process_exists(pid)) {
            continue;
        }

        const string cwd = read_proc_cwd(pid);
        if (cwd.empty()) {
            continue;
        }

        bool cwd_matches_runtime_dir = false;
        for (const string& runtime_dir : runtime_dirs) {
            const string runtime_root =
                normalize_proc_path_string((run_root_path / runtime_dir).string());
            if (path_is_same_or_descendant(cwd, runtime_root)) {
                cwd_matches_runtime_dir = true;
                break;
            }
        }

        if (cwd_matches_runtime_dir) {
            matches.insert(pid);
            continue;
        }

        if (cwd == run_root && !script_name.empty()) {
            const string cmdline = read_proc_cmdline(pid);
            if (cmdline.find(script_name) != string::npos &&
                cmdline.find(legion_script_dir()) != string::npos) {
                matches.insert(pid);
            }
        }
    }
}

static void signal_label_runtime_processes(const string& label,
                                           int signal_number,
                                           set<pid_t>* signaled = nullptr) {
    set<pid_t> matches;
    collect_label_runtime_processes(label, matches);
    for (pid_t pid : matches) {
        signal_pid_ignore_missing(pid, signal_number);
        if (signaled != nullptr) {
            signaled->insert(pid);
        }
    }
}

static bool has_label_runtime_processes(const string& label) {
    set<pid_t> matches;
    collect_label_runtime_processes(label, matches);
    return !matches.empty();
}

static vector<pid_t> collect_process_tree(pid_t root_pid) {
    vector<pid_t> tree;
    if (root_pid <= 0 || !process_exists(root_pid)) {
        return tree;
    }

    map<pid_t, vector<pid_t>> children_by_parent;
    std::error_code ec;
    for (const auto& entry : filesystem::directory_iterator("/proc", ec)) {
        if (ec) {
            break;
        }
        const string name = entry.path().filename().string();
        if (!is_pid_directory_name(name)) {
            continue;
        }
        pid_t pid = static_cast<pid_t>(stol(name));
        pid_t ppid = -1;
        if (read_proc_ppid(pid, ppid)) {
            children_by_parent[ppid].push_back(pid);
        }
    }

    vector<pid_t> stack;
    set<pid_t> seen;
    stack.push_back(root_pid);
    seen.insert(root_pid);
    while (!stack.empty()) {
        pid_t current = stack.back();
        stack.pop_back();
        tree.push_back(current);
        auto it = children_by_parent.find(current);
        if (it == children_by_parent.end()) {
            continue;
        }
        for (pid_t child : it->second) {
            if (seen.insert(child).second) {
                stack.push_back(child);
            }
        }
    }

    return tree;
}

static void signal_pid_ignore_missing(pid_t pid, int signal_number) {
    if (pid <= 0) {
        return;
    }
    if (kill(pid, signal_number) != 0 && errno != ESRCH) {
        return;
    }
}

static void signal_process_tree(pid_t root_pid, int signal_number, set<pid_t>* signaled = nullptr) {
    vector<pid_t> tree = collect_process_tree(root_pid);
    for (pid_t pid : tree) {
        signal_pid_ignore_missing(pid, signal_number);
        if (signaled != nullptr) {
            signaled->insert(pid);
        }
    }
}

static bool reap_finished_process_group(pid_t pid, int* status = nullptr) {
    if (pid <= 0) {
        return true;
    }

    int local_status = 0;
    pid_t rc = waitpid(pid, &local_status, WNOHANG);
    if (rc == 0) {
        return false;
    }
    if (status != nullptr && rc == pid) {
        *status = local_status;
    }
    return true;
}

static void stop_process_group(pid_t pid, const string& label) {
    if (pid <= 0) {
        return;
    }

    int status = 0;
    bool root_finished = reap_finished_process_group(pid, &status);
    if (root_finished && !has_label_runtime_processes(label)) {
        return;
    }

    set<pid_t> known_tree;
    for (int pass = 0; pass < 2; ++pass) {
        if (!root_finished) {
            kill(-pid, SIGCONT);
        }
        signal_process_tree(pid, SIGCONT, &known_tree);
        signal_label_runtime_processes(label, SIGCONT, &known_tree);
        usleep(100000);
        root_finished = reap_finished_process_group(pid, &status);
    }

    if (!root_finished && kill(-pid, SIGTERM) != 0 && errno != ESRCH) {
        std::cout << "[LEGION] warning: failed to SIGTERM " << label
                  << " process group " << pid << endl;
    }
    for (int pass = 0; pass < 2; ++pass) {
        signal_process_tree(pid, SIGTERM, &known_tree);
        signal_label_runtime_processes(label, SIGTERM, &known_tree);
        for (pid_t known_pid : known_tree) {
            signal_pid_ignore_missing(known_pid, SIGTERM);
        }
        usleep(100000);
        root_finished = reap_finished_process_group(pid, &status);
    }

    for (int waited = 0; waited < 10; ++waited) {
        root_finished = reap_finished_process_group(pid, &status);
        if (root_finished && !has_label_runtime_processes(label)) {
            for (pid_t known_pid : known_tree) {
                signal_pid_ignore_missing(known_pid, SIGTERM);
            }
            return;
        }
        signal_label_runtime_processes(label, SIGTERM, &known_tree);
        for (pid_t known_pid : known_tree) {
            signal_pid_ignore_missing(known_pid, SIGTERM);
        }
        sleep(1);
    }

    if (!root_finished && kill(-pid, SIGKILL) != 0 && errno != ESRCH) {
        std::cout << "[LEGION] warning: failed to SIGKILL " << label
                  << " process group " << pid << endl;
    }
    signal_process_tree(pid, SIGKILL, &known_tree);
    signal_label_runtime_processes(label, SIGKILL, &known_tree);
    for (pid_t known_pid : known_tree) {
        signal_pid_ignore_missing(known_pid, SIGKILL);
    }
    if (!root_finished) {
        waitpid(pid, &status, 0);
    }
}

static bool pause_process_group(pid_t pid, const string& label) {
    if (pid <= 0) {
        return false;
    }
    int status = 0;
    if (reap_finished_process_group(pid, &status)) {
        return false;
    }
    if (kill(-pid, SIGSTOP) != 0 && errno != ESRCH) {
        std::cout << "[LEGION] warning: failed to SIGSTOP " << label
                  << " process group " << pid << endl;
        return false;
    }
    signal_process_tree(pid, SIGSTOP);
    usleep(100000);
    signal_process_tree(pid, SIGSTOP);
    return true;
}

static bool resume_process_group(pid_t pid, const string& label) {
    if (pid <= 0) {
        return false;
    }
    int status = 0;
    if (reap_finished_process_group(pid, &status)) {
        return false;
    }
    if (kill(-pid, SIGCONT) != 0 && errno != ESRCH) {
        std::cout << "[LEGION] warning: failed to SIGCONT " << label
                  << " process group " << pid << endl;
        return false;
    }
    signal_process_tree(pid, SIGCONT);
    usleep(100000);
    signal_process_tree(pid, SIGCONT);
    return true;
}

static string monitor_report_path_for(const string& fuzzer_label, size_t round) {
    const filesystem::path report_dir = ".monitor_reports";
    filesystem::create_directories(report_dir);
    return (report_dir /
            (sanitize_eval_label(fuzzer_label) + "_" + to_string(round) + ".report")).string();
}

static string round_input_baseline_report_path(const string& fuzzer_label, size_t round) {
    const filesystem::path report_dir = ".round_input_baseline";
    filesystem::create_directories(report_dir);
    return (report_dir /
            (sanitize_eval_label(fuzzer_label) + "_" + to_string(round) + ".report")).string();
}

static bool evaluate_round_input_baseline(const string& fuzzer_label, size_t round) {
    const string report_path = round_input_baseline_report_path(fuzzer_label, round);
    if (filesystem::exists(report_path)) {
        filesystem::remove(report_path);
    }

    string command = "build/instrumentapp " + string(INITIAL_POOL_NAME) + " " + report_path;
    if (eval_seed_timeout > 0) {
        command += " --seed-timeout " + to_string(eval_seed_timeout);
    }
    std::cout << "[LEGION] evaluate round input baseline for " << fuzzer_label
              << " under " << INITIAL_POOL_NAME << endl;
    const int rc = run_command(command);
    if (rc != 0) {
        std::cout << "[LEGION] warning: failed to evaluate round input baseline for "
                  << fuzzer_label << ", using empty baseline report" << endl;
        return write_empty_report(report_path);
    }
    return true;
}

static size_t count_regular_files(const filesystem::path& dir_path) {
    if (!filesystem::exists(dir_path) || !filesystem::is_directory(dir_path)) {
        return 0;
    }

    size_t count = 0;
    for (const auto& entry : filesystem::directory_iterator(dir_path)) {
        if (filesystem::is_regular_file(entry.path())) {
            count++;
        }
    }
    return count;
}

static bool prepare_radamsa_eval_cmin(const string& source_seed_folder,
                                      const filesystem::path& cmin_seed_folder,
                                      const string& context) {
    const size_t source_files = count_regular_files(source_seed_folder);
    if (source_files == 0) {
        return false;
    }

    std::error_code ec;
    filesystem::create_directories(cmin_seed_folder.parent_path(), ec);
    filesystem::remove_all(cmin_seed_folder, ec);

    const string command = script_path("AFL.sh") + " minimize " +
                           shell_quote(source_seed_folder) + " " +
                           shell_quote(cmin_seed_folder.string());
    std::cout << "[LEGION] cmin Radamsa " << context
              << " evaluation seeds from " << source_seed_folder
              << " into " << cmin_seed_folder.string() << endl;
    const int rc = run_command(command);
    const size_t minimized_files = count_regular_files(cmin_seed_folder);
    if (rc != 0 || minimized_files == 0) {
        std::cout << "[LEGION] warning: Radamsa " << context
                  << " cmin failed or produced no seeds; fallback to "
                  << source_seed_folder << endl;
        filesystem::remove_all(cmin_seed_folder, ec);
        return false;
    }

    std::cout << "[LEGION] Radamsa " << context << " cmin kept "
              << minimized_files << " / " << source_files << " seeds" << endl;
    return true;
}

static void evaluate_fuzzer_corpus(const fuzzer_t& selected_fuzzer,
                                   size_t round,
                                   const string& local_seed_folder,
                                   const unordered_set<string>& round_initial_fingerprints) {
    string report_name = local_seed_folder + ".report";
    string eval_seed_folder = local_seed_folder;
    filesystem::path seed_report_dir =
        eval_seed_report_cache_dir(selected_fuzzer.label, round);
    eval_seed_delta_t delta;
    bool use_incremental_eval = prepare_incremental_eval_input(selected_fuzzer.label,
                                                              round,
                                                              local_seed_folder,
                                                              round_initial_fingerprints,
                                                              delta);
    if (use_incremental_eval) {
        eval_seed_folder = delta.input_dir;
        std::cout << "[LEGION] evaluate only new seeds for " << selected_fuzzer.label
                  << ": " << delta.new_files << " new vs round-start initial / "
                  << delta.total_files << " total in " << local_seed_folder << endl;
    } else {
        std::cout << "[LEGION] warning: failed to prepare incremental evaluation for "
                  << selected_fuzzer.label << ", fallback to full corpus" << endl;
    }

    if (selected_fuzzer.label == "Radamsa" &&
        !(use_incremental_eval && delta.new_files == 0)) {
        const filesystem::path cmin_dir = filesystem::path(".eval_cmin") /
                                          (sanitize_eval_label(selected_fuzzer.label) +
                                           "_" + to_string(round));
        if (prepare_radamsa_eval_cmin(eval_seed_folder, cmin_dir, "final")) {
            eval_seed_folder = cmin_dir.string();
        }
    }

    if (filesystem::exists(seed_report_dir)) {
        filesystem::remove_all(seed_report_dir);
    }
    filesystem::create_directories(seed_report_dir);

    string evaluate_command = "build/instrumentapp " + eval_seed_folder + " " + report_name;
    evaluate_command += " --seed-report-dir " + seed_report_dir.string();
    if (eval_seed_timeout > 0) {
        evaluate_command += " --seed-timeout " + to_string(eval_seed_timeout);
        std::cout << "[LEGION] per-seed evaluation timeout set to "
                  << eval_seed_timeout << " seconds" << endl;
    }
    std::cout << "[LEGION] evaluate performance of " << selected_fuzzer.label << endl;
    auto start = chrono::high_resolution_clock::now();
    int rc = 0;
    if (use_incremental_eval && delta.new_files == 0) {
        std::cout << "[LEGION] no new seeds to evaluate for " << selected_fuzzer.label << endl;
        rc = write_empty_report(report_name) ? 0 : 1;
    } else {
        rc = run_command(evaluate_command);
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    if (use_incremental_eval && rc == 0 &&
        !append_seen_fingerprints(delta.manifest_path, delta.new_fingerprints)) {
        std::cout << "[LEGION] warning: failed to update evaluated-seed manifest for "
                  << selected_fuzzer.label << endl;
    }
    std::cout << "[LEGION] finish evaluation run for " << selected_fuzzer.label
              << " in " << duration.count() / 1000 << " seconds" << endl;
}

static bool evaluate_monitor_corpus(const fuzzer_t& selected_fuzzer,
                                    size_t round,
                                    const string& local_seed_folder,
                                    const unordered_set<string>& round_initial_fingerprints,
                                    monitor_eval_input_t& input) {
    input.label = selected_fuzzer.label;
    input.report_path = monitor_report_path_for(selected_fuzzer.label, round);
    input.baseline_report_path = round_input_baseline_report_path(selected_fuzzer.label, round);

    eval_seed_delta_t delta;
    bool use_incremental_eval = prepare_monitor_eval_input(selected_fuzzer.label,
                                                           round,
                                                           local_seed_folder,
                                                           round_initial_fingerprints,
                                                           delta);
    string eval_seed_folder = use_incremental_eval ? delta.input_dir : local_seed_folder;

    if (selected_fuzzer.label == "Radamsa" &&
        !(use_incremental_eval && delta.new_files == 0)) {
        const filesystem::path cmin_dir = filesystem::path(".monitor_eval_cmin") /
                                          (sanitize_eval_label(selected_fuzzer.label) +
                                           "_" + to_string(round));
        if (prepare_radamsa_eval_cmin(eval_seed_folder, cmin_dir, "monitor")) {
            eval_seed_folder = cmin_dir.string();
        }
    }

    filesystem::path seed_report_dir = filesystem::path(".monitor_seed_reports") /
                                       (sanitize_eval_label(selected_fuzzer.label) +
                                        "_" + to_string(round));
    if (filesystem::exists(seed_report_dir)) {
        filesystem::remove_all(seed_report_dir);
    }
    filesystem::create_directories(seed_report_dir);

    string evaluate_command = "build/instrumentapp " + eval_seed_folder + " " + input.report_path;
    evaluate_command += " --seed-report-dir " + seed_report_dir.string();
    if (eval_seed_timeout > 0) {
        evaluate_command += " --seed-timeout " + to_string(eval_seed_timeout);
    }

    int rc = 0;
    if (use_incremental_eval && delta.new_files == 0) {
        rc = write_empty_report(input.report_path) ? 0 : 1;
    } else {
        rc = run_command(evaluate_command);
    }

    if (use_incremental_eval && rc == 0 &&
        !append_seen_fingerprints(delta.manifest_path, delta.new_fingerprints)) {
        std::cout << "[LEGION] warning: failed to update monitor manifest for "
                  << selected_fuzzer.label << endl;
    }
    return rc == 0;
}

static void finalize_round_fuzzer_outputs(const fuzzer_t& selected_fuzzer,
                                          size_t round,
                                          const unordered_set<string>& round_initial_fingerprints) {
    const string local_seed_folder = selected_fuzzer.label + to_string(round);
    export_staged_round_crashes(selected_fuzzer.label, round);

    archive_round_new_seeds(selected_fuzzer.label,
                            round,
                            local_seed_folder,
                            round_initial_fingerprints);

    // Keep per-fuzzer round outputs unminimized before evaluation/sync.
    // The -m flag still controls global-pool minimization elsewhere.

    if (!run_long) {
        evaluate_fuzzer_corpus(selected_fuzzer,
                               round,
                               local_seed_folder,
                               round_initial_fingerprints);
    }
}

static bool start_active_round_fuzzer(active_round_fuzzer_t& state,
                                      const fuzzer_t& selected_fuzzer,
                                      uint32_t execution_time) {
    if (state.scheduled_units == 0 || execution_time == 0) {
        return false;
    }

    ensure_clean_directory(state.live_seed_folder);
    const filesystem::path snapshot_dir =
        prepare_fuzzer_initial_snapshot(selected_fuzzer.label,
                                        state.accum_seed_folder,
                                        "run",
                                        0);

    if (uses_direct_persistent_worker(selected_fuzzer.label)) {
        if (!prepare_direct_runtime_dir(selected_fuzzer.label, snapshot_dir, true)) {
            return false;
        }

        state.groups.clear();
        state.next_worker_index = 1;

        if (uses_autofz_qsym_process_pool(selected_fuzzer.label)) {
            const string afl_command = build_direct_qsym_afl_command(0, true);
            std::cout << "[LEGION] running QSYM AFL master with command: "
                      << afl_command << endl;
            pid_t afl_pid = start_command_process_group(afl_command);
            if (afl_pid <= 0) {
                return false;
            }

            worker_process_group_t afl_group;
            afl_group.pid = afl_pid;
            afl_group.units = 1;
            afl_group.mode = "qsym-afl-master";
            afl_group.paused = false;
            state.groups.push_back(afl_group);

            const uint32_t wait_budget = std::min<uint32_t>(30, execution_time);
            if (!wait_for_file_path(filesystem::path("run_qsym") / "output" /
                                    "afl-master" / "fuzzer_stats",
                                    wait_budget)) {
                std::cout << "[LEGION] warning: QSYM AFL master did not create "
                          << "fuzzer_stats in time; stop QSYM base group" << endl;
                stop_persistent_round_fuzzer(state);
                return false;
            }

            const string qsym_command = build_direct_qsym_se_command();
            std::cout << "[LEGION] running QSYM symbolic executor with command: "
                      << qsym_command << endl;
            pid_t qsym_pid = start_command_process_group(qsym_command);
            if (qsym_pid <= 0) {
                stop_persistent_round_fuzzer(state);
                return false;
            }

            worker_process_group_t qsym_group;
            qsym_group.pid = qsym_pid;
            qsym_group.units = 1;
            qsym_group.mode = "qsym";
            qsym_group.paused = false;
            state.groups.push_back(qsym_group);

            state.scheduled_units = 2;
            state.next_worker_index = 1;
            state.active = true;
            return true;
        }

        const string worker_command = (selected_fuzzer.label == "LibFuzzer")
            ? build_direct_libfuzzer_worker_command()
            : build_direct_afl_worker_command(selected_fuzzer.label, 0, true);
        std::cout << "[LEGION] running " << selected_fuzzer.label
                  << " persistent worker with command: "
                  << worker_command << endl;
        pid_t pid = start_command_process_group(worker_command);
        if (pid <= 0) {
            return false;
        }

        worker_process_group_t group;
        group.pid = pid;
        group.units = 1;
        group.mode = (selected_fuzzer.label == "LibFuzzer") ? "libfuzzer" : "master";
        group.paused = false;
        state.groups.push_back(group);
        state.scheduled_units = 1;
        state.next_worker_index = 1;
        state.active = true;
        return true;
    }

    const string fuzz_command =
        with_private_initial_env(build_run_command(selected_fuzzer,
                                                   execution_time,
                                                   state.scheduled_units,
                                                   state.live_seed_folder),
                                 snapshot_dir);
    std::cout << "[LEGION] running " << selected_fuzzer.label
              << " with command: " << fuzz_command << endl;
    pid_t pid = start_command_process_group(fuzz_command);
    if (pid <= 0) {
        return false;
    }

    state.groups.clear();
    state.next_worker_index = 1;
    worker_process_group_t group;
    group.pid = pid;
    group.units = state.scheduled_units;
    group.mode = "run";
    group.paused = false;
    state.groups.push_back(group);
    state.active = true;
    return true;
}

static bool append_active_round_fuzzer(active_round_fuzzer_t& state,
                                       const fuzzer_t& selected_fuzzer,
                                       uint32_t execution_time,
                                       uint32_t additional_units) {
    if (additional_units == 0 || execution_time == 0 ||
        !supports_runtime_append(selected_fuzzer.label)) {
        return false;
    }

    const uint32_t append_worker_index = state.next_worker_index;
    const filesystem::path snapshot_dir =
        prepare_fuzzer_initial_snapshot(selected_fuzzer.label,
                                        state.accum_seed_folder,
                                        "append",
                                        append_worker_index);
    if (uses_direct_persistent_worker(selected_fuzzer.label)) {
        if (!prepare_direct_runtime_dir(selected_fuzzer.label, snapshot_dir, false)) {
            return false;
        }

        uint32_t started_units = 0;
        for (uint32_t offset = 0; offset < additional_units; ++offset) {
            const uint32_t worker_index = append_worker_index + offset;
            string worker_command;
            string mode;
            if (uses_autofz_qsym_process_pool(selected_fuzzer.label)) {
                worker_command = build_direct_qsym_afl_command(worker_index, false);
                mode = "qsym-afl-slave";
            } else if (selected_fuzzer.label == "LibFuzzer") {
                worker_command = build_direct_libfuzzer_worker_command();
                mode = "libfuzzer";
            } else {
                worker_command =
                    build_direct_afl_worker_command(selected_fuzzer.label,
                                                    worker_index,
                                                    false);
                mode = "slave";
            }

            std::cout << "[LEGION] expanding " << selected_fuzzer.label
                      << " with persistent worker command: "
                      << worker_command << endl;
            pid_t pid = start_command_process_group(worker_command);
            if (pid <= 0) {
                continue;
            }

            worker_process_group_t group;
            group.pid = pid;
            group.units = 1;
            group.mode = mode;
            group.paused = false;
            state.groups.push_back(group);
            started_units++;
            sleep(1);
        }

        if (started_units == 0) {
            return false;
        }

        state.scheduled_units += started_units;
        state.next_worker_index = append_worker_index + started_units;
        state.active = true;
        return true;
    }

    string append_command = build_append_command(selected_fuzzer,
                                                 execution_time,
                                                 additional_units,
                                                 state.live_seed_folder);
    if (uses_autofz_indexed_append(selected_fuzzer.label)) {
        append_command = "LEGION_APPEND_WORKER_INDEX=" +
                         to_string(append_worker_index) + " " +
                         append_command;
    }
    append_command = with_private_initial_env(append_command, snapshot_dir);
    std::cout << "[LEGION] expanding " << selected_fuzzer.label
              << " with command: " << append_command << endl;
    pid_t pid = start_command_process_group(append_command);
    if (pid <= 0) {
        return false;
    }

    worker_process_group_t group;
    group.pid = pid;
    group.units = additional_units;
    group.mode = "append";
    group.paused = false;
    state.groups.push_back(group);
    state.scheduled_units += additional_units;
    state.next_worker_index = append_worker_index + additional_units;
    state.active = true;
    return true;
}

static uint32_t total_round_fuzzer_units(const active_round_fuzzer_t& state) {
    uint32_t total_units = 0;
    for (const auto& group : state.groups) {
        total_units += group.units;
    }
    return total_units;
}

static uint32_t compact_active_round_fuzzer_groups(active_round_fuzzer_t& state) {
    vector<worker_process_group_t> survivors;
    uint32_t active_units = 0;

    for (auto group : state.groups) {
        int status = 0;
        if (!reap_finished_process_group(group.pid, &status)) {
            if (!group.paused) {
                active_units += group.units;
            }
            survivors.push_back(group);
        }
    }

    state.groups.swap(survivors);
    state.scheduled_units = active_units;
    state.active = active_units > 0;
    return active_units;
}

static void pause_round_fuzzer_to_units(active_round_fuzzer_t& state,
                                        uint32_t target_units) {
    uint32_t active_units = compact_active_round_fuzzer_groups(state);
    if (active_units <= target_units) {
        return;
    }

    for (auto it = state.groups.rbegin(); it != state.groups.rend() && active_units > target_units; ++it) {
        if (it->paused) {
            continue;
        }
        if (it->units > active_units - target_units && target_units != 0) {
            continue;
        }
        if (pause_process_group(it->pid, state.label)) {
            it->paused = true;
            active_units -= it->units;
        }
    }

    compact_active_round_fuzzer_groups(state);
}

static void resume_round_fuzzer_to_units(active_round_fuzzer_t& state,
                                         uint32_t target_units) {
    uint32_t active_units = compact_active_round_fuzzer_groups(state);
    if (active_units >= target_units) {
        return;
    }

    for (auto& group : state.groups) {
        if (!group.paused) {
            continue;
        }
        if (resume_process_group(group.pid, state.label)) {
            group.paused = false;
            active_units += group.units;
        }
        if (active_units >= target_units) {
            break;
        }
    }

    compact_active_round_fuzzer_groups(state);
}

static void pause_active_round_fuzzer(active_round_fuzzer_t& state,
                                      size_t round,
                                      bool collect_outputs) {
    compact_active_round_fuzzer_groups(state);
    for (auto& group : state.groups) {
        if (!group.paused && pause_process_group(group.pid, state.label)) {
            group.paused = true;
        }
    }
    state.scheduled_units = 0;
    state.accounting_units = 0;
    state.active = false;
    if (collect_outputs) {
        collect_active_round_outputs(state);
        stage_current_round_crashes(state.label, round);
    }
}

static void stop_persistent_round_fuzzer(active_round_fuzzer_t& state) {
    for (const auto& group : state.groups) {
        stop_process_group(group.pid, state.label);
    }
    state.groups.clear();
    state.scheduled_units = 0;
    state.accounting_units = 0;
    state.active = false;
}

static uint32_t persistent_worker_timeout(size_t round) {
    uint64_t remaining_rounds = (round_number > round) ? (round_number - round) : 1;
    uint64_t base = remaining_rounds * static_cast<uint64_t>(round_time);
    uint64_t slack = std::max<uint64_t>(86400, static_cast<uint64_t>(round_time) * 2);
    uint64_t timeout = base + slack;
    if (timeout > 2000000000ULL) {
        return 2000000000U;
    }
    return static_cast<uint32_t>(timeout);
}

static bool ensure_active_round_fuzzer_units(active_round_fuzzer_t& state,
                                             const fuzzer_t& selected_fuzzer,
                                             size_t round,
                                             uint32_t target_units) {
    if (target_units == 0) {
        pause_active_round_fuzzer(state, round, true);
        return false;
    }

    const uint32_t worker_timeout = uses_fresh_round_process(selected_fuzzer.label)
        ? round_time
        : persistent_worker_timeout(round);
    compact_active_round_fuzzer_groups(state);

    if (uses_autofz_afl_process_pool(selected_fuzzer.label)) {
        const uint32_t pool_units = std::max<uint32_t>(1, resource_unit_number);
        if (state.groups.empty()) {
            state.scheduled_units = 1;
            if (!start_active_round_fuzzer(state, selected_fuzzer, worker_timeout)) {
                state.scheduled_units = 0;
                return false;
            }
            std::cout << "[LEGION] prestarting AutoFZ-style worker pool for "
                      << selected_fuzzer.label << ": 1 master + "
                      << (pool_units > 0 ? pool_units - 1 : 0)
                      << " paused slave candidates" << endl;
        }

        while (total_round_fuzzer_units(state) < pool_units) {
            if (!append_active_round_fuzzer(state, selected_fuzzer, worker_timeout, 1)) {
                break;
            }
            pause_round_fuzzer_to_units(state, target_units);
            sleep(1);
        }

        resume_round_fuzzer_to_units(state, target_units);
        pause_round_fuzzer_to_units(state, target_units);
        return compact_active_round_fuzzer_groups(state) > 0;
    }

    if (uses_autofz_qsym_process_pool(selected_fuzzer.label)) {
        const uint32_t effective_target = target_units;
        if (state.groups.empty()) {
            state.scheduled_units = 2;
            if (!start_active_round_fuzzer(state, selected_fuzzer, worker_timeout)) {
                state.scheduled_units = 0;
                return false;
            }
            std::cout << "[LEGION] started AutoFZ-style QSYM base group: "
                      << "1 AFL master + 1 QSYM symbolic executor" << endl;
        }

        resume_round_fuzzer_to_units(state, effective_target);

        while (compact_active_round_fuzzer_groups(state) < effective_target) {
            if (!append_active_round_fuzzer(state, selected_fuzzer, worker_timeout, 1)) {
                break;
            }
        }

        pause_round_fuzzer_to_units(state, effective_target);
        return compact_active_round_fuzzer_groups(state) > 0;
    }

    if (state.groups.empty()) {
        state.scheduled_units = uses_fresh_round_process(selected_fuzzer.label)
            ? target_units
            : 1;
        if (!start_active_round_fuzzer(state, selected_fuzzer, worker_timeout)) {
            state.scheduled_units = 0;
            return false;
        }
    }

    resume_round_fuzzer_to_units(state, target_units);

    while (compact_active_round_fuzzer_groups(state) < target_units) {
        if (!append_active_round_fuzzer(state, selected_fuzzer, worker_timeout, 1)) {
            break;
        }
    }

    pause_round_fuzzer_to_units(state, target_units);
    return compact_active_round_fuzzer_groups(state) > 0;
}

static void collect_active_round_outputs(active_round_fuzzer_t& state) {
    filesystem::create_directories(state.live_seed_folder);
    snapshot_runtime_outputs_for_label(state.label, state.live_seed_folder);
    merge_seed_folder_into_accum(state.live_seed_folder, state.accum_seed_folder);
}

static void stop_active_round_fuzzer(active_round_fuzzer_t& state,
                                     size_t round,
                                     bool force_stop) {
    if (!state.active && state.groups.empty()) {
        collect_active_round_outputs(state);
        return;
    }

    if (force_stop) {
        for (const auto& group : state.groups) {
            stop_process_group(group.pid, state.label);
        }
        state.groups.clear();
        state.scheduled_units = 0;
        state.active = false;
    } else {
        compact_active_round_fuzzer_groups(state);
    }

    collect_active_round_outputs(state);
    stage_current_round_crashes(state.label, round);
}

static bool select_metric_contributing_sync_seeds(const string& fuzzer_label,
                                                  size_t round,
                                                  eval_seed_delta_t& delta) {
    auto target_it = fuzzer_sync_targets.find(fuzzer_label);
    if (target_it == fuzzer_sync_targets.end()) {
        return false;
    }

    sync_metric_targets_t remaining = target_it->second;
    const size_t original_target_count = sync_metric_targets_count(remaining);
    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path selected_root = ".sync_selected";
    const filesystem::path selected_dir = selected_root / (safe_label + "_" + to_string(round));

    filesystem::create_directories(selected_root);
    if (filesystem::exists(selected_dir)) {
        filesystem::remove_all(selected_dir);
    }
    filesystem::create_directories(selected_dir);

    if (sync_metric_targets_empty(remaining)) {
        std::cout << "[LEGION] no c0-c4 sync targets for " << fuzzer_label
                  << ", skip syncing round-new seeds" << endl;
        delta.input_dir = selected_dir.string();
        delta.new_fingerprints.clear();
        delta.new_files = 0;
        return true;
    }

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(delta.input_dir)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    vector<string> selected_fingerprints;
    size_t selected = 0;
    size_t evaluated = 0;
    size_t cache_hits = 0;
    size_t cache_misses = 0;
    size_t fallback_replays = 0;
    const filesystem::path temp_root = filesystem::path(".sync_eval_tmp") /
                                       (safe_label + "_" + to_string(round));
    bool temp_root_ready = false;

    for (size_t index = 0; index < seed_files.size(); ++index) {
        if (sync_metric_targets_empty(remaining)) {
            break;
        }

        const filesystem::path& seed_path = seed_files[index];
        sync_seed_features_t features;
        features.fingerprint = eval_file_fingerprint(seed_path);
        bool have_features = load_cached_sync_seed_features(fuzzer_label, round, features);
        if (have_features) {
            cache_hits++;
        } else {
            cache_misses++;
            if (!temp_root_ready) {
                if (filesystem::exists(temp_root)) {
                    filesystem::remove_all(temp_root);
                }
                filesystem::create_directories(temp_root);
                temp_root_ready = true;
            }
            if (collect_sync_seed_features_via_replay(seed_path, temp_root, index, features)) {
                fallback_replays++;
            }
        }
        evaluated++;

        if (sync_seed_has_metric_contribution(features, remaining)) {
            filesystem::copy_file(seed_path,
                                  selected_dir / seed_path.filename(),
                                  filesystem::copy_options::overwrite_existing);
            selected_fingerprints.push_back(features.fingerprint);
            consume_sync_metric_targets(features, remaining);
            selected++;
        }

    }

    if (temp_root_ready) {
        filesystem::remove_all(temp_root);
    }

    delta.input_dir = selected_dir.string();
    delta.new_fingerprints = selected_fingerprints;
    delta.new_files = delta.new_fingerprints.size();

    std::cout << "[LEGION] metric-aware sync filter for " << fuzzer_label
              << ": selected " << selected << " / " << seed_files.size()
              << " seeds after checking " << evaluated
              << " (cache hits=" << cache_hits
              << ", cache misses=" << cache_misses
              << ", fallback replays=" << fallback_replays << ")"
              << ", uncovered c0-c4 targets left=" << sync_metric_targets_count(remaining)
              << " / " << original_target_count << endl;
    return true;
}

static bool write_empty_report(const string& report_name) {
    ofstream out(report_name);
    if (!out.is_open()) {
        return false;
    }

    out << "[EDGE]" << endl;
    out << "[PATH]" << endl;
    out << "[EDGE TO FUNC]" << endl;
    return true;
}

static unordered_set<string> collect_directory_fingerprints(const string& seed_dir) {
    unordered_set<string> fingerprints;
    if (!filesystem::exists(seed_dir) || !filesystem::is_directory(seed_dir)) {
        return fingerprints;
    }

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(seed_dir)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    for (const auto& seed_path : seed_files) {
        fingerprints.insert(eval_file_fingerprint(seed_path));
    }
    return fingerprints;
}

static bool prepare_incremental_eval_input(const string& fuzzer_label,
                                           size_t round,
                                           const string& local_seed_folder,
                                           const unordered_set<string>& round_initial_fingerprints,
                                           eval_seed_delta_t& delta) {
    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path state_dir = ".eval_state";
    const filesystem::path delta_root = ".eval_delta";
    const filesystem::path delta_dir = delta_root / (safe_label + "_" + to_string(round));

    filesystem::create_directories(state_dir);
    filesystem::create_directories(delta_root);
    if (filesystem::exists(delta_dir)) {
        filesystem::remove_all(delta_dir);
    }
    filesystem::create_directories(delta_dir);

    delta.input_dir = delta_dir.string();
    delta.manifest_path = state_dir / (safe_label + ".manifest");

    unordered_set<string> historical_fingerprints;
    if (!load_seen_fingerprints(delta.manifest_path, historical_fingerprints)) {
        return false;
    }

    if (!filesystem::exists(local_seed_folder) || !filesystem::is_directory(local_seed_folder)) {
        return true;
    }

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(local_seed_folder)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    unordered_set<string> round_unique_fingerprints;
    for (const auto& seed_path : seed_files) {
        delta.total_files++;
        string fingerprint = eval_file_fingerprint(seed_path);
        if (round_initial_fingerprints.count(fingerprint) > 0) {
            continue;
        }
        if (!round_unique_fingerprints.insert(fingerprint).second) {
            continue;
        }
        if (historical_fingerprints.count(fingerprint) > 0) {
            continue;
        }

        filesystem::copy_file(seed_path,
                              delta_dir / seed_path.filename(),
                              filesystem::copy_options::overwrite_existing);
        delta.new_fingerprints.push_back(fingerprint);
    }

    delta.new_files = delta.new_fingerprints.size();
    return true;
}

static bool prepare_incremental_sync_input(const string& fuzzer_label,
                                           size_t round,
                                           const string& local_seed_folder,
                                           const unordered_set<string>& round_initial_fingerprints,
                                           eval_seed_delta_t& delta) {
    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path state_dir = ".sync_state";
    const filesystem::path delta_root = ".sync_delta";
    const filesystem::path delta_dir = delta_root / (safe_label + "_" + to_string(round));

    filesystem::create_directories(state_dir);
    filesystem::create_directories(delta_root);
    if (filesystem::exists(delta_dir)) {
        filesystem::remove_all(delta_dir);
    }
    filesystem::create_directories(delta_dir);

    delta.input_dir = delta_dir.string();
    delta.manifest_path = state_dir / (safe_label + "_" + to_string(round) + ".manifest");

    unordered_set<string> synced_fingerprints;
    if (!load_seen_fingerprints(delta.manifest_path, synced_fingerprints)) {
        return false;
    }

    if (!filesystem::exists(local_seed_folder) || !filesystem::is_directory(local_seed_folder)) {
        return true;
    }

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(local_seed_folder)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    unordered_set<string> round_unique_fingerprints;
    for (const auto& seed_path : seed_files) {
        delta.total_files++;
        string fingerprint = eval_file_fingerprint(seed_path);
        if (round_initial_fingerprints.count(fingerprint) > 0) {
            continue;
        }
        if (!round_unique_fingerprints.insert(fingerprint).second) {
            continue;
        }
        if (synced_fingerprints.count(fingerprint) > 0) {
            continue;
        }

        filesystem::copy_file(seed_path,
                              delta_dir / seed_path.filename(),
                              filesystem::copy_options::overwrite_existing);
        delta.new_fingerprints.push_back(fingerprint);
    }

    delta.new_files = delta.new_fingerprints.size();
    return true;
}

static bool prepare_monitor_eval_input(const string& fuzzer_label,
                                       size_t round,
                                       const string& local_seed_folder,
                                       const unordered_set<string>& round_initial_fingerprints,
                                       eval_seed_delta_t& delta) {
    const string safe_label = sanitize_eval_label(fuzzer_label);
    const filesystem::path state_dir = ".monitor_eval_state";
    const filesystem::path delta_root = ".monitor_eval_delta";
    const filesystem::path delta_dir = delta_root / (safe_label + "_" + to_string(round));

    filesystem::create_directories(state_dir);
    filesystem::create_directories(delta_root);
    if (filesystem::exists(delta_dir)) {
        filesystem::remove_all(delta_dir);
    }
    filesystem::create_directories(delta_dir);

    delta.input_dir = delta_dir.string();
    delta.manifest_path = state_dir / (safe_label + "_" + to_string(round) + ".manifest");

    unordered_set<string> seen_fingerprints;
    if (!load_seen_fingerprints(delta.manifest_path, seen_fingerprints)) {
        return false;
    }

    if (!filesystem::exists(local_seed_folder) || !filesystem::is_directory(local_seed_folder)) {
        return true;
    }

    vector<filesystem::path> seed_files;
    for (const auto& entry : filesystem::directory_iterator(local_seed_folder)) {
        if (!filesystem::is_regular_file(entry.path())) {
            continue;
        }
        seed_files.push_back(entry.path());
    }
    sort(seed_files.begin(), seed_files.end());

    unordered_set<string> round_unique_fingerprints;
    for (const auto& seed_path : seed_files) {
        delta.total_files++;
        const string fingerprint = eval_file_fingerprint(seed_path);
        if (round_initial_fingerprints.count(fingerprint) > 0) {
            continue;
        }
        if (!round_unique_fingerprints.insert(fingerprint).second) {
            continue;
        }
        if (seen_fingerprints.count(fingerprint) > 0) {
            continue;
        }

        filesystem::copy_file(seed_path,
                              delta_dir / seed_path.filename(),
                              filesystem::copy_options::overwrite_existing);
        delta.new_fingerprints.push_back(fingerprint);
    }

    delta.new_files = delta.new_fingerprints.size();
    return true;
}

void parse_args(int argc, char* argv[]) {
    size_t i = 1;
    while ( i < argc )
    {
        string arg = argv[i];
        if ( arg == "--build" || arg == "-b" ) {
            to_build = true;
        } else if ( arg == "-r" || arg == "--run" ) {
            to_run = true;
            if (arg == "--run") {
                run_long = true;
            }
        } else if (arg == "-m") {
            do_minimize = true;
        } else if ( arg == "--aflpp" ) {
            use_aflpp = true;
        } else if ( arg == "--hongg" ) {
            use_hongg = true;
        } else if ( arg == "--libfuzzer") {
            use_libfuzzer = true;
        } else if ( arg == "--radamsa") {
            use_radamsa = true;
        } else if ( arg == "--qsym" ) {
            use_qsym = true;
        } else if ( arg == "--afl" ) {
            use_afl = true;
        } else if ( arg == "--aflfast" ) {
            use_aflfast = true;
        } else if ( arg == "--fairfuzz" ) {
            use_fairfuzz = true;
        } else if ( arg == "--angora" ) {
            use_angora = true;
        } else if ( arg == "--dict") {
            use_dictionary = true;
        } else if ( arg == "-zip" || arg == "-gz") {
            compress_format = arg;
        } else if ( arg == "--resource") {
            ++i;
            resource_unit_number = stoi(argv[i]);
        } else if ( arg == "--round") {
            ++i;
            round_number = stoi(argv[i]);
        } else if ( arg == "--round-time") {
            ++i;
            round_time = stoi(argv[i]);
        } else if ( arg == "--eval-seed-timeout") {
            ++i;
            eval_seed_timeout = stoi(argv[i]);
        } else if ( arg == "--initial" ) {
            ++i;
            initial_seed_file = argv[i];
        } else {
            source_path = arg;
        }
        i++;
    }       
}

void build_binary(string script_name) {
    string instrument_build_command = script_path(script_name) + " build " + compress_format + " " + source_path + " --call-graph";
    system(instrument_build_command.c_str());
}

void build() {
    if (compress_format == "" || source_path == "" ) {
        std::cout << "[ERROR] build without given compress type of source path." << endl;
        return;
    }
    // the instrumented binary we use to evaluate each fuzzer
    string instrument_build_command = script_path("INSTRUMENT.sh") + " build " + compress_format + " " + source_path + " --call-graph";
    system(instrument_build_command.c_str());

    if (use_aflpp) {
        build_binary("AFLPP.sh");        
    }

    if (use_hongg) {
        build_binary("HONGG.sh");
    }

    if (use_libfuzzer) {
        build_binary("LIBFUZZER.sh");
    }

    if (use_radamsa) {
        build_binary("RADAMSA.sh");
    }

    if (use_qsym) {
        build_binary("QSYM.sh");
    }

    if (use_afl) {
        build_binary("AFL.sh");
    }

    if (use_aflfast) {
        build_binary("AFLFast.sh");
    }

    if (use_fairfuzz) {
        build_binary("FairFuzz.sh");
    }

    if (use_angora) {
        build_binary("Angora.sh");
    }
}


int run_command(string command) {
    return system(command.c_str());
}

void pull_seeds(string seed_folder) {
    string command = "find " + seed_folder + "/ -type f -name \'*\' -print0 | xargs -0 -r cp --target-directory=./" + GLOBAL_POOL_NAME;
    system(command.c_str());
}

static void cleanup_round_seed_folder(const string& fuzzer_label, size_t round) {
    filesystem::path local_seed_folder = fuzzer_label + to_string(round);
    if (!filesystem::exists(local_seed_folder)) {
        return;
    }

    std::error_code ec;
    filesystem::remove_all(local_seed_folder, ec);
    if (ec) {
        std::cout << "[LEGION] warning: failed to remove round seed folder "
                  << local_seed_folder << ": " << ec.message() << endl;
    } else {
        std::cout << "[LEGION] cleaned round seed folder " << local_seed_folder << endl;
    }
}

static void cleanup_path_if_exists(const filesystem::path& path_to_remove) {
    if (!filesystem::exists(path_to_remove)) {
        return;
    }

    std::error_code last_ec;
    for (int attempt = 0; attempt < 5; ++attempt) {
        last_ec.clear();
        filesystem::remove_all(path_to_remove, last_ec);
        if (!filesystem::exists(path_to_remove)) {
            std::cout << "[LEGION] cleaned " << path_to_remove << endl;
            return;
        }
        sleep(1);
    }

    const string fallback_command = "rm -rf -- " + shell_quote(path_to_remove.string());
    system(fallback_command.c_str());
    if (!filesystem::exists(path_to_remove)) {
        std::cout << "[LEGION] cleaned " << path_to_remove << endl;
        return;
    }

    if (last_ec) {
        std::cout << "[LEGION] warning: failed to remove "
                  << path_to_remove << ": " << last_ec.message() << endl;
    } else {
        std::cout << "[LEGION] warning: failed to remove "
                  << path_to_remove << ": path still exists after cleanup" << endl;
    }
}

static void sync_round_new_seeds_to_global(const string& fuzzer_label,
                                           size_t round,
                                           const unordered_set<string>& round_initial_fingerprints) {
    string local_seed_folder = fuzzer_label + to_string(round);
    eval_seed_delta_t delta;
    bool use_incremental_sync = prepare_incremental_sync_input(fuzzer_label,
                                                               round,
                                                               local_seed_folder,
                                                               round_initial_fingerprints,
                                                               delta);
    if (!use_incremental_sync) {
        std::cout << "[LEGION] warning: failed to prepare incremental sync for "
                  << fuzzer_label
                  << ", skip global sync to preserve round-delta semantics" << endl;
        return;
    }

    std::cout << "[LEGION] sync only round-new seeds for " << fuzzer_label
              << ": " << delta.new_files << " new vs round-start initial / "
              << delta.total_files << " total in " << local_seed_folder << endl;
    if (delta.new_files == 0) {
        return;
    }

    if (!select_metric_contributing_sync_seeds(fuzzer_label, round, delta)) {
        std::cout << "[LEGION] warning: no c0-c4 sync targets recorded for "
                  << fuzzer_label << ", fallback to syncing all round-new seeds" << endl;
    }

    std::cout << "[LEGION] final sync selection for " << fuzzer_label
              << ": " << delta.new_files << " seeds will be merged into global" << endl;
    if (delta.new_files == 0) {
        return;
    }

    pull_seeds(delta.input_dir);
    if (!append_seen_fingerprints(delta.manifest_path, delta.new_fingerprints)) {
        std::cout << "[LEGION] warning: failed to update synced-seed manifest for "
                  << fuzzer_label << endl;
    }
}

static void refresh_synced_global_record(size_t round) {
    const string report_path = ".global_synced_round_" + to_string(round) + ".report";
    string command = "build/instrumentapp " + string(GLOBAL_POOL_NAME) + " " + report_path;
    if (eval_seed_timeout > 0) {
        command += " --seed-timeout " + to_string(eval_seed_timeout);
    }
    std::cout << "[LEGION] refresh global fuzzing record M from synced global pool" << endl;
    run_command(command);
    refresh_global_record_from_report(report_path);
}

void minimize_corpus(string seed_folder, string tmp_folder = "tmp") {
    std::cout << "[LEGION] minimize seeds under folder " << seed_folder << endl;
    string command = "rm -rf " + tmp_folder + " ; mkdir " + tmp_folder +
                     " && " + script_path("AFLPP.sh") + " minimize " + seed_folder + " " + tmp_folder +
                     " && rm -rf " + seed_folder + " && mkdir " + seed_folder +
                     " && mv " + tmp_folder + "/* " + seed_folder + "/ && rm -rf " + tmp_folder;
    system(command.c_str());
  //  string command = "honggfuzz -i " + seed_folder + " -P -M -- ./build/honggapp ___FILE___";
    // string command = "mkdir tmp && time ./build/libapp -merge=1 tmp " + seed_folder + " && rm " + seed_folder + "/* && mv tmp/* " + seed_folder + " && rm -rf tmp";
    // system(command.c_str());
}

static string current_global_input_pool_for_fuzzers() {
    if (do_minimize && filesystem::exists(GLOBAL_CMIN_INPUT_POOL_NAME)) {
        return string(GLOBAL_CMIN_INPUT_POOL_NAME);
    }
    return string(GLOBAL_POOL_NAME);
}

static void update_fuzzers_from_current_global_input(vector<fuzzer_t>& fuzzers) {
    const string source_pool = current_global_input_pool_for_fuzzers();
    std::cout << "[LEGION] update active fuzzer seed queues from "
              << source_pool << endl;
    for (auto& fuzzer : fuzzers) {
        update_seed(source_pool, fuzzer);
    }
}

void refresh_global_cmin_input_pool() {
    const string tmp_folder = string(GLOBAL_CMIN_INPUT_POOL_NAME) + "_tmp";
    std::cout << "[LEGION] refresh minimized fuzzer input pool from global under "
              << GLOBAL_CMIN_INPUT_POOL_NAME << endl;
    string command = "rm -rf " + tmp_folder + " ; mkdir " + tmp_folder +
                     " && " + script_path("AFLPP.sh") + " minimize " + string(GLOBAL_POOL_NAME) + " " + tmp_folder +
                     " && rm -rf " + string(GLOBAL_CMIN_INPUT_POOL_NAME) +
                     " && mkdir " + string(GLOBAL_CMIN_INPUT_POOL_NAME) +
                     " && mv " + tmp_folder + "/* " + string(GLOBAL_CMIN_INPUT_POOL_NAME) +
                     "/ && rm -rf " + tmp_folder;
    system(command.c_str());
}

void update_seed(string seed_folder, fuzzer_t fuzzer) {
    string command = fuzzer.script + " update " + seed_folder;
    system(command.c_str());
}

static map<uint32_t, uint32_t> allocate_resource_units(const vector<fuzzer_t>& fuzzers, size_t round) {
    map<uint32_t, uint32_t> selected_fuzzers;
    if (fuzzers.empty() || resource_unit_number == 0) {
        return selected_fuzzers;
    }

    if (round == 0) {
        std::cout << "[LEGION] round #0 uses one-shot priming allocation" << endl;
        const size_t priming_units =
            std::min<size_t>(resource_unit_number, fuzzers.size());

        if (resource_unit_number < fuzzers.size()) {
            std::cout << "[LEGION] warning: resource units are fewer than fuzzers; "
                      << "not all fuzzers can be primed in round #0" << endl;
        }

        for (size_t i = 0; i < priming_units; ++i) {
            selected_fuzzers[i] = 1;
        }

        if (resource_unit_number > fuzzers.size()) {
            std::cout << "[LEGION] round #0 leaves "
                      << (resource_unit_number - fuzzers.size())
                      << " resource units idle to keep one-shot priming semantics"
                      << endl;
        }
        return selected_fuzzers;
    }

    std::cout << "[LEGION] round #" << round << " uses probability-based resource allocation" << endl;
    for (size_t i = 0; i < resource_unit_number; ++i) {
        uint32_t index = select(fuzzers);
        if (index >= fuzzers.size()) {
            break;
        }
        selected_fuzzers[index]++;
    }
    return selected_fuzzers;
}


void fuzz_one_fuzzer(vector<fuzzer_t>& fuzzers,
                     uint32_t first,
                     uint32_t scheduled_units,
                     size_t round,
                     const unordered_set<string>& round_initial_fingerprints) {
    fuzzer_t selected_fuzzer = fuzzers[first];
    std::cout << "[LEGION] schedule " << scheduled_units << " resource units for " << selected_fuzzer.label << endl;
    string local_seed_folder = selected_fuzzer.label + to_string(round);
    // uint32_t execution_time = (run_long) ? round_time * round_number : round_time;
    uint32_t execution_time = round_time;
    string fuzz_command = selected_fuzzer.script + " run " + to_string(execution_time) + " " + to_string(scheduled_units) + " " + local_seed_folder;
    if (use_dictionary) {
        fuzz_command = fuzz_command + " -d";
    }
    std::cout << "[LEGION] running " << selected_fuzzer.label << " with command: " << fuzz_command << endl;
    run_command(fuzz_command);
    archive_round_crash_seeds(selected_fuzzer.label, round);

    archive_round_new_seeds(selected_fuzzer.label,
                            round,
                            local_seed_folder,
                            round_initial_fingerprints);

    // Keep per-fuzzer round outputs unminimized before evaluation/sync.
    // The -m flag still controls global-pool minimization elsewhere.
    if (! run_long) {
        string report_name = local_seed_folder + ".report";
        string eval_seed_folder = local_seed_folder;
        filesystem::path seed_report_dir =
            eval_seed_report_cache_dir(selected_fuzzer.label, round);
        eval_seed_delta_t delta;
        bool use_incremental_eval = prepare_incremental_eval_input(selected_fuzzer.label,
                                                                  round,
                                                                  local_seed_folder,
                                                                  round_initial_fingerprints,
                                                                  delta);
        if (use_incremental_eval) {
            eval_seed_folder = delta.input_dir;
            std::cout << "[LEGION] evaluate only new seeds for " << selected_fuzzer.label
                      << ": " << delta.new_files << " new vs round-start initial / "
                      << delta.total_files << " total in " << local_seed_folder << endl;
        } else {
            std::cout << "[LEGION] warning: failed to prepare incremental evaluation for "
                      << selected_fuzzer.label << ", fallback to full corpus" << endl;
        }

        if (filesystem::exists(seed_report_dir)) {
            filesystem::remove_all(seed_report_dir);
        }
        filesystem::create_directories(seed_report_dir);

        string evaluate_command = "build/instrumentapp " + eval_seed_folder + " " + report_name;
        evaluate_command += " --seed-report-dir " + seed_report_dir.string();
        if (eval_seed_timeout > 0) {
            evaluate_command += " --seed-timeout " + to_string(eval_seed_timeout);
            std::cout << "[LEGION] per-seed evaluation timeout set to "
                      << eval_seed_timeout << " seconds" << endl;
        }
        std::cout << "[LEGION] evaluate performance of " << selected_fuzzer.label << endl;
        auto start = chrono::high_resolution_clock::now();
        int rc = 0;
        if (use_incremental_eval && delta.new_files == 0) {
            std::cout << "[LEGION] no new seeds to evaluate for " << selected_fuzzer.label << endl;
            rc = write_empty_report(report_name) ? 0 : 1;
        } else {
            rc = run_command(evaluate_command);
        }
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
        if (use_incremental_eval && rc == 0 &&
            !append_seen_fingerprints(delta.manifest_path, delta.new_fingerprints)) {
            std::cout << "[LEGION] warning: failed to update evaluated-seed manifest for "
                      << selected_fuzzer.label << endl;
        }
        std::cout << "[LEGION] finish evaluation run for " << selected_fuzzer.label <<" in " << duration.count() / 1000 << " seconds" << endl;

    }
}



// execute time seconds in total. Every 10 minutes sync only round-new seeds into the global seed folder.
void wait_and_pull(vector<fuzzer_t>& fuzzers,
                   size_t round,
                   size_t time,
                   const unordered_set<string>& round_initial_fingerprints) {
    std::cout << "[LEGION] guard thread monitoring " << time << " seconds" << endl;
    int time_count = 0;
    int sleep_duration = 600;
    int round_count = 0;
    int mini_time = 0;
    while (time_count < time) {
        if (sleep_duration >= time - time_count) {
            std::cout << "[LEGION] the last round, no need to do this, guard thread exit" << endl;
            break;
        }
        int sleep_time = max(sleep_duration - mini_time, 0);
        std::cout << "[LEGION] last round minimization took "<< mini_time <<", guard thread sleep for " << sleep_time << " seconds, overall time has " << time - time_count << " seconds." << endl;
        sleep(sleep_time);
        time_count += sleep_duration;
        round_count++;
        std::cout << "[LEGION] guard thread wake up for round " << round_count
                  << ", sync round-new seeds to global pool" << endl;
        for (auto& fuzzer : fuzzers) {
            sync_round_new_seeds_to_global(fuzzer.label, round, round_initial_fingerprints);
        }
        //calculate the execution time of the following command in second
        auto start = chrono::high_resolution_clock::now();
        refresh_global_cmin_input_pool();
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
        mini_time = duration.count() / 1000;
        std::cout << "[LEGION] finish minimization in " << mini_time << " seconds" << endl;
        update_fuzzers_from_current_global_input(fuzzers);
    }
}



void run_one_long_round(vector<fuzzer_t>& fuzzers, size_t round) {
    map<uint32_t, uint32_t> selected_fuzzers = allocate_resource_units(fuzzers, round);


    string global = GLOBAL_POOL_NAME;
    string initial = INITIAL_POOL_NAME;
    string command = script_path("SEED.sh") + " refill " + global + " " + initial;
    system(command.c_str());
    unordered_set<string> round_initial_fingerprints = collect_directory_fingerprints(INITIAL_POOL_NAME);

    vector<thread> fuzz_threads;
    for (auto& it : selected_fuzzers ) {
        
        fuzzer_t selected_fuzzer = fuzzers[it.first];
        uint32_t scheduled_units = it.second;
       // cout << "[DEBUG] refecth: "<< round << " data: " << it.first << " " << selected_fuzzer.label <<" "<< it.second << endl;

        //fuzz_one_fuzzer(selected_fuzzer, scheduled_units, round);
        fuzz_threads.push_back(thread(fuzz_one_fuzzer,
                                      ref(fuzzers),
                                      it.first,
                                      scheduled_units,
                                      round,
                                      cref(round_initial_fingerprints)));
       // sleep(1);
    }

    // 5 seconds delay to make sure all fuzzers are ready
    sleep(5);
    
    if (run_long) {
        thread t(wait_and_pull,
                 ref(fuzzers),
                 round,
                 round_time * round_number,
                 cref(round_initial_fingerprints));
        t.join();
    }
    

    for (auto& t : fuzz_threads) {
        t.join();
    }

    update_global_record();

    for (auto& fuzzer : fuzzers) {
        sync_round_new_seeds_to_global(fuzzer.label, round, round_initial_fingerprints);
    }
    refresh_synced_global_record(round);
    for (auto& fuzzer : fuzzers) {
        cleanup_round_seed_folder(fuzzer.label, round);
    }
    if (do_minimize) {
        std::cout << "[LEGION] minimizing final results" << endl;
        refresh_global_cmin_input_pool();
    }
    record_enfuzz_path_metrics(round, fuzzers);
    //std::cout << "[LEGION] finish fuzzing round #" << round << endl;
    
}

void run_one_round(vector<fuzzer_t>& fuzzers,
                   size_t round,
                   vector<string> deep_function,
                   map<uint32_t, active_round_fuzzer_t>& active_states) {
    map<uint32_t, uint32_t> selected_fuzzers = allocate_resource_units(fuzzers, round);
    unordered_set<uint32_t> selected_indices;
    vector<uint32_t> round_active_indices;
    map<uint32_t, double> accounted_selected_fuzzers;
    for (const auto& it : selected_fuzzers) {
        selected_indices.insert(it.first);
        accounted_selected_fuzzers[it.first] = static_cast<double>(it.second);
    }

    string global = (do_minimize && filesystem::exists(GLOBAL_CMIN_INPUT_POOL_NAME))
        ? string(GLOBAL_CMIN_INPUT_POOL_NAME)
        : string(GLOBAL_POOL_NAME);
    string initial = INITIAL_POOL_NAME;
    string command = script_path("SEED.sh") + " refill " + global + " " + initial;
    system(command.c_str());
    unordered_set<string> round_initial_fingerprints = collect_directory_fingerprints(INITIAL_POOL_NAME);
    reset_monitor_state();

    map<uint32_t, string> round_input_baseline_reports;
    for (const auto& it : selected_fuzzers) {
        const fuzzer_t& selected_fuzzer = fuzzers[it.first];
        evaluate_round_input_baseline(selected_fuzzer.label, round);
        round_input_baseline_reports[it.first] =
            round_input_baseline_report_path(selected_fuzzer.label, round);
    }

    for (auto& entry : active_states) {
        if (selected_indices.count(entry.first) == 0 && !entry.second.groups.empty()) {
            if (uses_fresh_round_process(entry.second.label)) {
                stop_persistent_round_fuzzer(entry.second);
            } else {
                pause_active_round_fuzzer(entry.second, round, false);
            }
        }
    }

    for (auto& it : selected_fuzzers) {
        fuzzer_t selected_fuzzer = fuzzers[it.first];
        active_round_fuzzer_t& state = active_states[it.first];
        state.fuzzer_index = it.first;
        state.label = selected_fuzzer.label;
        if (uses_fresh_round_process(state.label) && !state.groups.empty()) {
            stop_persistent_round_fuzzer(state);
        }
        state.accum_seed_folder = selected_fuzzer.label + to_string(round);
        state.live_seed_folder = state.accum_seed_folder + "_live";
        state.monitor_report_path = monitor_report_path_for(selected_fuzzer.label, round);
        state.cumulative_monitor_reward = 0.0;

        ensure_clean_directory(state.accum_seed_folder);
        ensure_clean_directory(state.live_seed_folder);
        ensure_clean_directory(staged_round_crash_dir(selected_fuzzer.label, round));

        if (!state.groups.empty()) {
            update_seed(current_global_input_pool_for_fuzzers(), selected_fuzzer);
        }

        const uint32_t requested_units = it.second;
        const uint32_t runtime_units =
            runtime_resource_units_for_fuzzer(selected_fuzzer.label, requested_units);
        std::cout << "[LEGION] schedule " << requested_units
                  << " resource units for " << selected_fuzzer.label;
        if (runtime_units != requested_units) {
            std::cout << " (runtime units=" << runtime_units << ")";
        }
        std::cout << endl;
        if (ensure_active_round_fuzzer_units(state, selected_fuzzer, round, runtime_units)) {
            state.accounting_units = requested_units;
            round_active_indices.push_back(it.first);
        } else {
            state.accounting_units = 0;
        }
        sleep(1);
    }

    const size_t monitor_start = round_time / 2;
    size_t elapsed = 0;
    while (elapsed < round_time) {
        size_t sleep_step = 0;
        if (elapsed < monitor_start) {
            sleep_step = monitor_start - elapsed;
        } else {
            sleep_step = std::min<size_t>(MONITOR_TIME, round_time - elapsed);
        }
        if (sleep_step == 0) {
            break;
        }

        sleep(sleep_step);
        elapsed += sleep_step;

        if (elapsed < monitor_start) {
            continue;
        }

        vector<uint32_t> currently_active;
        for (uint32_t fuzzer_index : round_active_indices) {
            active_round_fuzzer_t& state = active_states[fuzzer_index];
            stop_active_round_fuzzer(state, round, false);
            if (state.active) {
                currently_active.push_back(fuzzer_index);
            }
        }

        if (currently_active.empty()) {
            continue;
        }

        vector<monitor_eval_input_t> monitor_inputs;
        for (uint32_t fuzzer_index : currently_active) {
            monitor_eval_input_t input;
            const active_round_fuzzer_t& state = active_states[fuzzer_index];
            if (!evaluate_monitor_corpus(fuzzers[fuzzer_index],
                                         round,
                                         state.accum_seed_folder,
                                         round_initial_fingerprints,
                                         input)) {
                std::cout << "[LEGION] warning: monitor evaluation failed for "
                          << state.label << endl;
            }
            monitor_inputs.push_back(input);
        }

        monitor_eval_result_t monitor_result =
            evaluate_monitor_window(monitor_inputs, deep_function);

        double best_reward = 0.0;
        int32_t best_index = -1;
        bool any_window_reward = false;
        for (uint32_t fuzzer_index : currently_active) {
            active_round_fuzzer_t& state = active_states[fuzzer_index];
            double window_reward = 0.0;
            auto it_reward = monitor_result.rewards.find(state.label);
            if (it_reward != monitor_result.rewards.end()) {
                window_reward = it_reward->second;
            }
            if (window_reward > 0.0) {
                any_window_reward = true;
            }
            state.cumulative_monitor_reward += window_reward;
            std::cout << "[LEGION] monitor reward for " << state.label
                      << ": window=" << window_reward
                      << ", cumulative=" << state.cumulative_monitor_reward << endl;
            if (state.cumulative_monitor_reward > best_reward) {
                best_reward = state.cumulative_monitor_reward;
                best_index = static_cast<int32_t>(fuzzer_index);
            }
        }

        if (!any_window_reward) {
            std::cout << "[LEGION] no active fuzzer has generated beneficial seeds; "
                      << "terminating current round early" << endl;
            break;
        }

        vector<uint32_t> donors;
        uint32_t reclaimed_units = 0;
        for (uint32_t fuzzer_index : currently_active) {
            if (static_cast<int32_t>(fuzzer_index) == best_index) {
                continue;
            }

            const string& label = active_states[fuzzer_index].label;
            double window_reward = 0.0;
            auto it_reward = monitor_result.rewards.find(label);
            if (it_reward != monitor_result.rewards.end()) {
                window_reward = it_reward->second;
            }
            if (window_reward == 0.0 && active_states[fuzzer_index].accounting_units > 0) {
                donors.push_back(fuzzer_index);
                reclaimed_units += active_states[fuzzer_index].accounting_units;
            }
        }

        if (donors.empty() || reclaimed_units == 0) {
            continue;
        }

        const size_t remaining_time = (elapsed >= round_time) ? 0 : (round_time - elapsed);
        const double remaining_fraction = (round_time > 0)
            ? (static_cast<double>(remaining_time) / static_cast<double>(round_time))
            : 0.0;
        active_round_fuzzer_t& best_state = active_states[best_index];
        std::cout << "[LEGION] reclaim " << reclaimed_units
                  << " resource units from stagnated fuzzers and assign them to "
                  << best_state.label << endl;

        for (uint32_t donor_index : donors) {
            active_round_fuzzer_t& donor_state = active_states[donor_index];
            const uint32_t donor_accounting_units = donor_state.accounting_units;
            std::cout << "[LEGION] reclaim all " << donor_accounting_units
                      << " resource units from " << donor_state.label << endl;
            accounted_selected_fuzzers[donor_index] -=
                static_cast<double>(donor_accounting_units) * remaining_fraction;
            if (uses_fresh_round_process(donor_state.label)) {
                stop_active_round_fuzzer(donor_state, round, true);
            } else {
                pause_active_round_fuzzer(donor_state, round, true);
            }
        }

        accounted_selected_fuzzers[best_index] +=
            static_cast<double>(reclaimed_units) * remaining_fraction;

        if (remaining_time == 0) {
            continue;
        }

        const uint32_t boosted_accounting_units = best_state.accounting_units + reclaimed_units;
        const uint32_t boosted_runtime_units =
            runtime_resource_units_for_fuzzer(best_state.label, boosted_accounting_units);
        bool expanded = ensure_active_round_fuzzer_units(best_state,
                                                         fuzzers[best_index],
                                                         round,
                                                         boosted_runtime_units);
        if (!expanded) {
            std::cout << "[LEGION] runtime append is unavailable for "
                      << best_state.label
                      << ", keep existing persistent workers without restart" << endl;
        } else {
            best_state.accounting_units = boosted_accounting_units;
        }
    }

    for (uint32_t fuzzer_index : round_active_indices) {
        active_round_fuzzer_t& state = active_states[fuzzer_index];
        if (uses_fresh_round_process(state.label)) {
            stop_active_round_fuzzer(state, round, true);
        } else {
            pause_active_round_fuzzer(state, round, true);
        }
    }

    for (auto& it : selected_fuzzers) {
        finalize_round_fuzzer_outputs(fuzzers[it.first],
                                      round,
                                      round_initial_fingerprints);
    }

    evaluate_all(accounted_selected_fuzzers,
                 fuzzers,
                 deep_function,
                 round,
                 round_input_baseline_reports);
    update_global_record();

    for (auto& fuzzer : fuzzers) {
        sync_round_new_seeds_to_global(fuzzer.label, round, round_initial_fingerprints);
    }
    refresh_synced_global_record(round);
    for (auto& fuzzer : fuzzers) {
        cleanup_round_seed_folder(fuzzer.label, round);
        cleanup_path_if_exists(filesystem::path(fuzzer.label + to_string(round) + "_live"));
        cleanup_path_if_exists(staged_round_crash_dir(fuzzer.label, round));
    }
    
    if (do_minimize) {
        refresh_global_cmin_input_pool();
    }

    record_enfuzz_path_metrics(round, fuzzers);

    std::cout << "[LEGION] finish fuzzing round #" << round << endl;


    
}

void run() {

    if (!filesystem::exists("build/instrumentapp")) {
        std::cout << "[ERROR] no instrumented app for evaluation. did you run the build phase?" << endl;
        return;
    }
    

    vector<fuzzer_t> fuzzers;
    if (use_aflpp) {
        add_fuzzer(fuzzers, "AFL++", "build/aflppapp", script_path("AFLPP.sh"));
        //std::cout << fuzzers.size() << endl;
    }
    if (use_hongg) {
        add_fuzzer(fuzzers, "HonggFuzz", "build/honggapp", script_path("HONGG.sh"));
        //std::cout << fuzzers.size() << endl;
    }
    if (use_libfuzzer) {
        add_fuzzer(fuzzers, "LibFuzzer", "build/libapp", script_path("LIBFUZZER.sh"));
        //std::cout << fuzzers.size() << endl;
    }
    if (use_qsym) {
        add_fuzzer(fuzzers, "QSYM", "build/qsymapp", script_path("QSYM.sh"));
    }
    if (use_afl) {
        add_fuzzer(fuzzers, "AFL", "build/aflapp", script_path("AFL.sh"));
    }
    if (use_aflfast) {
        add_fuzzer(fuzzers, "AFLFast", "build/aflfastapp", script_path("AFLFast.sh"));
    }

    if (use_fairfuzz) {
        add_fuzzer(fuzzers, "FairFuzz", "build/fairfuzzapp", script_path("FairFuzz.sh"));
    }

    
    if (use_angora) {
        add_fuzzer(fuzzers, "Angora", "build/angoraapp", script_path("Angora.sh"));
    }

    if (use_radamsa) {
        add_fuzzer(fuzzers, "Radamsa", NO_BINARY, script_path("RADAMSA.sh"));
        //tool_scripts.push_back("RADAMSA.sh");
        //std::cout << fuzzers.size() << endl;
    }
    if (fuzzers.empty())
    {
        std::cout << "[ERROR] seems like you did not specify any fuzzer to run or there is no corresponding binaries under build folder" << endl;
        return;
    }

    for (size_t i = 0; i < fuzzers.size(); i++)
    {
        std::cout << "[LEGION] using fuzzer " << fuzzers[i].label << endl;
    }
    

    std::cout << "[LEGION] analyzing call graph to identify deep functions" << endl;
    string dot_file = "./build/cgraph.dot";
    vector<string> deep_function = find_deep_functions(dot_file);

    
    for (size_t i = 0; i < deep_function.size(); i++)
    {
        std::cout << "[LEGION] deep functions that are reachable from the driver function: " << deep_function[i] << endl;
    }


    std::cout << "[LEGION] create global seed pool" << endl;
    filesystem::create_directories(GLOBAL_POOL_NAME);
    filesystem::create_directories(INITIAL_POOL_NAME);

    string seed_op = (initial_seed_file == "") ? "create " : "copy ";
    string seed_command = script_path("SEED.sh") + " " + seed_op + initial_seed_file + " " + GLOBAL_POOL_NAME;
    system(seed_command.c_str());
    if (do_minimize) {
        refresh_global_cmin_input_pool();
    }

    std::cout << "[LEGION] initialize initial seed coverage baseline" << endl;
    string baseline_report = ".initial_seed_baseline.report";
    string baseline_command = "build/instrumentapp " + string(GLOBAL_POOL_NAME) + " " + baseline_report;
    if (eval_seed_timeout > 0) {
        baseline_command += " --seed-timeout " + to_string(eval_seed_timeout);
    }
    if (run_command(baseline_command) == 0) {
        initialize_global_seed_baseline(baseline_report);
    } else {
        std::cout << "[LEGION] warning: failed to initialize initial seed coverage baseline" << endl;
    }

    std::cout << "[LEGION] let's fuzz " << round_number << " rounds of " << round_time << " seconds!" << endl;

    map<uint32_t, active_round_fuzzer_t> persistent_active_states;

    for (size_t i = 0; i < round_number; i++) {
        if (run_long) {
            run_one_long_round(fuzzers, i);
            break;
        } else {
            std::cout << "[LEGION] running #" << i << " round!" <<endl;
            run_one_round(fuzzers, i, deep_function, persistent_active_states);
        }
    }

    for (auto& entry : persistent_active_states) {
        stop_persistent_round_fuzzer(entry.second);
    }
    cleanup_path_if_exists(filesystem::path(FUZZER_INPUT_SNAPSHOT_ROOT));
    

}

int main(int argc, char* argv[]) {
    parse_args(argc, argv);

    // do build first, in case two phases are in a row
    if (to_build) {
        std::cout << "[LEGION] build projects" << endl;
        build();
        std::cout << "[LEGION] finish building, find binaries in build folder" << endl;
    }

    if (to_run) {
        std::cout << "[LEGION] run fuzzers!" << endl;
        run();
        std::cout << "[LEGION] finish running!" << endl;
    }
    

    return 0;
}
