#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <cmath>
#include <numeric>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include "global_record.h"


using namespace std;

double N = 0.0;
std::map<std::string, double> fuzzer_scores;
std::map<std::string, double> fuzzer_u;
std::map<std::string, double> fuzzer_probabilities;
std::map<std::string, sync_metric_targets_t> fuzzer_sync_targets;
static std::map<std::string, double> fuzzer_cumulative_rewards;
static std::map<std::string, double> fuzzer_last_rewards;
static std::map<std::string, double> fuzzer_effective_units;
static std::unordered_set<unsigned long> seen_edges_global;
static std::unordered_set<unsigned long> seen_paths_global;
static std::unordered_set<std::string> seen_crash_fingerprints_global;
static std::vector<unsigned long> global_edge_frequency_counts;
static bool global_seed_baseline_initialized = false;
static std::unordered_set<unsigned long> monitor_seen_edges_global;
static std::unordered_set<unsigned long> monitor_seen_paths_global;
static std::unordered_set<std::string> monitor_seen_crash_fingerprints_global;
static const double Q_INIT = 0.0;
static const double U_INIT = 1.0;

static void add_edge_counts(vector<unsigned long>& dst,
                            const vector<unsigned long>& src) {
    if (src.size() > dst.size()) {
        dst.resize(src.size(), 0);
    }
    for (size_t i = 0; i < src.size(); ++i) {
        dst[i] += src[i];
    }
}

static void add_report_edge_counts(const string& report_name,
                                   vector<unsigned long>& edge_counts) {
    ifstream rf(report_name);
    if (!rf.is_open()) return;

    enum Section { NONE, EDGE } section = NONE;
    string line;
    while (getline(rf, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '[') {
            if (line.rfind("[EDGE]", 0) == 0) { section = EDGE; continue; }
            section = NONE;
            continue;
        }
        if (section == EDGE) {
            unsigned long id = 0, val = 0;
            if (sscanf(line.c_str(), "%lu %lu", &id, &val) >= 1) {
                if (id >= edge_counts.size()) {
                    edge_counts.resize(max((size_t)1024, edge_counts.size()), 0);
                }
                while (id >= edge_counts.size()) {
                    edge_counts.resize(edge_counts.size() * 2, 0);
                }
                edge_counts[id] += val;
            }
        }
    }
}

void initialize_global_seed_baseline(const std::string& report_path) {
    if (global_seed_baseline_initialized) {
        std::cout << "[LEGION] initial seed coverage baseline already initialized" << endl;
        return;
    }

    ifstream rf(report_path);
    if (!rf.is_open()) {
        std::cout << "[LEGION] warning: failed to open initial seed baseline report "
                  << report_path << endl;
        return;
    }

    enum Section { NONE, EDGE, PATH } section = NONE;
    string line;
    vector<unsigned long> baseline_edge_counts;
    unordered_set<unsigned long> baseline_edges;
    unordered_set<unsigned long> baseline_paths;

    while (getline(rf, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '[') {
            if (line.rfind("[EDGE]", 0) == 0) { section = EDGE; continue; }
            if (line.rfind("[PATH]", 0) == 0) { section = PATH; continue; }
            section = NONE;
            continue;
        }

        if (section == EDGE) {
            unsigned long id = 0, val = 0;
            if (sscanf(line.c_str(), "%lu %lu", &id, &val) >= 1) {
                if (id >= baseline_edge_counts.size()) {
                    baseline_edge_counts.resize(max((size_t)1024, baseline_edge_counts.size()), 0);
                }
                while (id >= baseline_edge_counts.size()) {
                    baseline_edge_counts.resize(baseline_edge_counts.size() * 2, 0);
                }
                baseline_edge_counts[id] += val;
                if (val > 0) {
                    baseline_edges.insert(id);
                }
            }
        } else if (section == PATH) {
            std::istringstream iss(line);
            unsigned long h = 0;
            if (iss >> h) {
                baseline_paths.insert(h);
            }
        }
    }

    seen_edges_global.insert(baseline_edges.begin(), baseline_edges.end());
    seen_paths_global.insert(baseline_paths.begin(), baseline_paths.end());
    add_edge_counts(global_edge_frequency_counts, baseline_edge_counts);
    global_seed_baseline_initialized = true;

    std::cout << "[LEGION] initialized initial seed coverage baseline: edges="
              << baseline_edges.size()
              << ", paths=" << baseline_paths.size()
              << endl;
}

void refresh_global_record_from_report(const std::string& report_path) {
    ifstream rf(report_path);
    if (!rf.is_open()) {
        std::cout << "[LEGION] warning: failed to open global sync report "
                  << report_path << endl;
        return;
    }

    enum Section { NONE, EDGE, PATH } section = NONE;
    string line;
    vector<unsigned long> edge_counts;
    unordered_set<unsigned long> covered_edges;
    unordered_set<unsigned long> covered_paths;

    while (getline(rf, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '[') {
            if (line.rfind("[EDGE]", 0) == 0) { section = EDGE; continue; }
            if (line.rfind("[PATH]", 0) == 0) { section = PATH; continue; }
            section = NONE;
            continue;
        }

        if (section == EDGE) {
            unsigned long id = 0, val = 0;
            if (sscanf(line.c_str(), "%lu %lu", &id, &val) >= 1) {
                if (id >= edge_counts.size()) {
                    edge_counts.resize(max((size_t)1024, edge_counts.size()), 0);
                }
                while (id >= edge_counts.size()) {
                    edge_counts.resize(edge_counts.size() * 2, 0);
                }
                edge_counts[id] = val;
                if (val > 0) {
                    covered_edges.insert(id);
                }
            }
        } else if (section == PATH) {
            std::istringstream iss(line);
            unsigned long h = 0;
            if (iss >> h) {
                covered_paths.insert(h);
            }
        }
    }

    global_edge_frequency_counts = edge_counts;
    seen_edges_global = covered_edges;
    seen_paths_global = covered_paths;
    monitor_seen_edges_global = seen_edges_global;
    monitor_seen_paths_global = seen_paths_global;

    std::cout << "[LEGION] refreshed global fuzzing record from synced global pool: edges="
              << seen_edges_global.size()
              << ", paths=" << seen_paths_global.size()
              << endl;
}

static bool is_valid_crash_file(const filesystem::path& p) {
    if (!filesystem::is_regular_file(p)) return false;
    string name = p.filename().string();
    if (name.empty()) return false;
    if (name == "README.txt" || name == "README" || name[0] == '.') return false;
    return true;
}

static bool is_honggfuzz_crash_file(const filesystem::path& p) {
    if (!is_valid_crash_file(p)) return false;
    const string name = p.filename().string();
    static const vector<string> signal_prefixes = {
        "SIGSEGV.", "SIGABRT.", "SIGILL.", "SIGFPE.", "SIGBUS.", "SIGTRAP."
    };
    for (const auto& prefix : signal_prefixes) {
        if (name.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

static string file_fingerprint(const filesystem::path& p) {
    ifstream in(p, ios::binary);
    if (!in.is_open()) return p.string();
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

static void collect_dir_crashes(const filesystem::path& run_output_root, vector<string>& out) {
    if (!filesystem::exists(run_output_root) || !filesystem::is_directory(run_output_root)) return;
    for (const auto& fdir : filesystem::directory_iterator(run_output_root)) {
        if (!filesystem::is_directory(fdir.path())) continue;
        filesystem::path crashes_dir = fdir.path() / "crashes";
        if (!filesystem::exists(crashes_dir) || !filesystem::is_directory(crashes_dir)) continue;
        for (const auto& entry : filesystem::directory_iterator(crashes_dir)) {
            if (!is_valid_crash_file(entry.path())) continue;
            out.push_back(file_fingerprint(entry.path()));
        }
    }
}

static void collect_honggfuzz_crashes(const filesystem::path& run_root, vector<string>& out) {
    if (!filesystem::exists(run_root) || !filesystem::is_directory(run_root)) return;
    for (const auto& entry : filesystem::directory_iterator(run_root)) {
        if (is_honggfuzz_crash_file(entry.path())) {
            out.push_back(file_fingerprint(entry.path()));
        }
    }

    const filesystem::path output_dir = run_root / "output";
    if (!filesystem::exists(output_dir) || !filesystem::is_directory(output_dir)) return;
    for (const auto& entry : filesystem::directory_iterator(output_dir)) {
        if (is_honggfuzz_crash_file(entry.path())) {
            out.push_back(file_fingerprint(entry.path()));
        }
    }
}

static vector<string> collect_crash_fingerprints_for_fuzzer(const string& fuzzer_label) {
    vector<string> fingerprints;
    if (fuzzer_label == "LibFuzzer") {
        filesystem::path outdir = "run_lib/output";
        if (filesystem::exists(outdir) && filesystem::is_directory(outdir)) {
            for (const auto& entry : filesystem::directory_iterator(outdir)) {
                if (!filesystem::is_regular_file(entry.path())) continue;
                string fname = entry.path().filename().string();
                if (fname.rfind("crash", 0) == 0) fingerprints.push_back(file_fingerprint(entry.path()));
            }
        }
        return fingerprints;
    }

    if (fuzzer_label == "HonggFuzz") {
        collect_honggfuzz_crashes("run_hongg", fingerprints);
        return fingerprints;
    }

    static const unordered_map<string, string> run_roots = {
        {"AFL++", "run_aflpp/output"},
        {"AFL", "run_afl/output"},
        {"AFLFast", "run_aflfast/output"},
        {"FairFuzz", "run_fairfuzz/output"},
        {"Angora", "run_angora/output"},
        {"QSYM", "run_qsym/output"}
    };

    auto it = run_roots.find(fuzzer_label);
    if (it != run_roots.end()) {
        collect_dir_crashes(it->second, fingerprints);
    }
    return fingerprints;
}

// Global variables
// uint32_t N = 0; // Sum of all scheduled_units
// map<string, double> fuzzer_scores; // Map to store scores for each fuzzer
// map<string, double> fuzzer_u; // Map to store u for each fuzzer
// map<string, double> fuzzer_probabilities; // Map to store probabilities for each fuzzer

struct report_profile_t {
    vector<unsigned long> edge_counts;
    vector<string> edge_funcs;
    std::unordered_set<unsigned long> covered_edges;
    std::unordered_set<unsigned long> covered_paths;
    double edge_hit_sum = 0.0;
};

struct parsed_report_metrics_t {
    vector<unsigned long> metrics = vector<unsigned long>(5, 0);
    sync_metric_targets_t metric_targets;
    std::unordered_set<unsigned long> covered_edges;
    std::unordered_set<unsigned long> covered_paths;
    std::unordered_set<std::string> crash_fingerprints;
};

static report_profile_t parse_report_profile(const string& report_path) {
    report_profile_t profile;
    ifstream rf(report_path);
    if (!rf.is_open()) return profile;

    enum Section { NONE, EDGE, PATH, EDGE_TO_FUNC, CRASH_SECTION } section = NONE;
    string line;

    auto ensure_cap = [&](size_t idx) {
        if (idx < profile.edge_counts.size()) return;
        size_t newcap = max((size_t)1024, profile.edge_counts.size());
        if (newcap == 0) newcap = 1024;
        while (idx >= newcap) newcap *= 2;
        profile.edge_counts.resize(newcap, 0);
        profile.edge_funcs.resize(newcap);
    };

    while (getline(rf, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '[') {
            if (line.rfind("[EDGE TO FUNC]", 0) == 0) { section = EDGE_TO_FUNC; continue; }
            if (line.rfind("[EDGE]", 0) == 0) { section = EDGE; continue; }
            if (line.rfind("[PATH]", 0) == 0) { section = PATH; continue; }
            // if (line.rfind("[CRASH]", 0) == 0 || line.rfind("[CRASHES]", 0) == 0) { section = CRASH_SECTION; continue; }
            section = NONE;
            continue;
        }

        if (section == EDGE) {
            unsigned long id = 0, val = 0;
            if (sscanf(line.c_str(), "%lu %lu", &id, &val) >= 1) {
                ensure_cap(id);
                profile.edge_counts[id] = val;
                if (val > 0) {
                    profile.edge_hit_sum += (double)val;
                    profile.covered_edges.insert(id);
                }
            }
        } else if (section == PATH) {
            std::istringstream iss(line);
            unsigned long h = 0;
            if (!(iss >> h)) continue;
            profile.covered_paths.insert(h);
        } else if (section == EDGE_TO_FUNC) {
            unsigned long id = 0;
            size_t pos = line.find_first_of(" \t");
            if (pos != string::npos) {
                string idstr = line.substr(0, pos);
                try {
                    id = stoul(idstr);
                } catch (...) {
                    continue;
                }
                string fname = line.substr(pos + 1);
                // trim leading/trailing whitespace
                size_t start = fname.find_first_not_of(" \t");
                size_t end = fname.find_last_not_of(" \t");
                if (start == string::npos) fname = "";
                else fname = fname.substr(start, end - start + 1);
                ensure_cap(id);
                profile.edge_funcs[id] = fname;
            } else {
                std::istringstream iss(line);
                if (iss >> id) {
                    string fname;
                    if (std::getline(iss, fname)) {
                        size_t start = fname.find_first_not_of(" \t");
                        size_t end = fname.find_last_not_of(" \t");
                        if (start == string::npos) fname = "";
                        else fname = fname.substr(start, end - start + 1);
                        ensure_cap(id);
                        profile.edge_funcs[id] = fname;
                    }
                }
            }
        } 
    }
    rf.close();
    return profile;
}

static unsigned long edge_count_at(const vector<unsigned long>& counts, size_t id) {
    return id < counts.size() ? counts[id] : 0;
}

// Parse a fuzzer's saved corpus report and compute C0..C4 as a delta from
// the seed corpus that was handed to that fuzzer at the start of this round.
static parsed_report_metrics_t parse_report_metrics(
    const string& report_path,
    const string& baseline_report_path,
    const string& fuzzer_label,
    const vector<string>& deep_function,
    const std::unordered_set<std::string>& seen_crashes_before_round,
    const vector<unsigned long>* global_edge_counts = nullptr,
    const std::unordered_set<unsigned long>* already_rewarded_edges = nullptr,
    const std::unordered_set<unsigned long>* already_rewarded_paths = nullptr) {
    parsed_report_metrics_t parsed;
    report_profile_t final_profile = parse_report_profile(report_path);
    report_profile_t baseline_profile = baseline_report_path.empty()
        ? report_profile_t()
        : parse_report_profile(baseline_report_path);

    parsed.covered_edges = final_profile.covered_edges;
    parsed.covered_paths = final_profile.covered_paths;

    unsigned long c0_edges = 0;
    unsigned long c1_paths = 0;
    unsigned long c2_crashes = 0;
    unsigned long c3_deep_edges = 0;
    unsigned long c4_less_freq = 0;

    vector<string> crashes = collect_crash_fingerprints_for_fuzzer(fuzzer_label);
    for (const auto& fp : crashes) {
        parsed.crash_fingerprints.insert(fp);
        if (seen_crashes_before_round.count(fp) == 0) {
            c2_crashes++;
            parsed.metric_targets.c2_crashes.insert(fp);
        }
    }

    for (unsigned long path_hash : final_profile.covered_paths) {
        if (baseline_profile.covered_paths.count(path_hash) == 0) {
            if (already_rewarded_paths != nullptr &&
                already_rewarded_paths->count(path_hash) > 0) {
                continue;
            }
            c1_paths++;
            parsed.metric_targets.c1_paths.insert(static_cast<uint32_t>(path_hash));
        }
    }

    const size_t max_edge_count = max(final_profile.edge_counts.size(),
                                      baseline_profile.edge_counts.size());
    for (size_t id = 0; id < max_edge_count; ++id) {
        const unsigned long final_cnt = edge_count_at(final_profile.edge_counts, id);
        const unsigned long baseline_cnt = edge_count_at(baseline_profile.edge_counts, id);
        if (final_cnt <= baseline_cnt) {
            continue;
        }
        if (already_rewarded_edges != nullptr &&
            already_rewarded_edges->count(id) > 0) {
            continue;
        }

        if (baseline_cnt == 0) {
            c0_edges++;
            parsed.metric_targets.c0_edges.insert(id);
        }

        if (id < final_profile.edge_funcs.size() && !final_profile.edge_funcs[id].empty()) {
            for (const auto &df : deep_function) {
                if (final_profile.edge_funcs[id].find(df) != string::npos) {
                    c3_deep_edges++;
                    parsed.metric_targets.c3_deep_edges.insert(id);
                    break;
                }
            }
        }
    }

    double mu = 0.0;
    double thresh = 0.0;
    if (global_edge_counts && !global_edge_counts->empty()) {
        // compute mu from campaign-wide aggregated edge counts
        unsigned long g_covered = 0;
        double g_sum = 0.0;
        for (size_t i = 0; i < global_edge_counts->size(); ++i) {
            unsigned long v = (*global_edge_counts)[i];
            if (v > 0) { g_sum += (double)v; g_covered++; }
        }
        if (g_covered > 0) mu = g_sum / (double)g_covered;
        thresh = mu / 2.0;

        for (size_t id = 0; id < max_edge_count; ++id) {
            const unsigned long final_cnt = edge_count_at(final_profile.edge_counts, id);
            const unsigned long baseline_cnt = edge_count_at(baseline_profile.edge_counts, id);
            if (final_cnt > baseline_cnt && id < global_edge_counts->size()) {
                if (already_rewarded_edges != nullptr &&
                    already_rewarded_edges->count(id) > 0) {
                    continue;
                }
                const unsigned long global_cnt = (*global_edge_counts)[id];
                if (global_cnt > 0 && (double)global_cnt < thresh) {
                    c4_less_freq++;
                    parsed.metric_targets.c4_low_freq_edges.insert(id);
                }
            }
        }
    } else {
        if (!final_profile.covered_edges.empty()) {
            mu = final_profile.edge_hit_sum / (double)final_profile.covered_edges.size();
        }
        thresh = mu / 2.0;
        for (size_t id = 0; id < max_edge_count; ++id) {
            const unsigned long final_cnt = edge_count_at(final_profile.edge_counts, id);
            const unsigned long baseline_cnt = edge_count_at(baseline_profile.edge_counts, id);
            if (final_cnt > baseline_cnt && (double)final_cnt < thresh) {
                if (already_rewarded_edges != nullptr &&
                    already_rewarded_edges->count(id) > 0) {
                    continue;
                }
                c4_less_freq++;
                parsed.metric_targets.c4_low_freq_edges.insert(id);
            }
        }
    }

    std::cout << "[LEGION] report metrics for " << report_path << ": c0=" << c0_edges << ", c1=" << c1_paths << ", c2=" << c2_crashes
              << ", c3=" << c3_deep_edges << ", c4=" << c4_less_freq
              << " (baseline=" << (baseline_report_path.empty() ? "<empty>" : baseline_report_path)
              << ")" << endl;
    parsed.metrics[0] = c0_edges;
    parsed.metrics[1] = c1_paths;
    parsed.metrics[2] = c2_crashes;
    parsed.metrics[3] = c3_deep_edges;
    parsed.metrics[4] = c4_less_freq;
    return parsed;
}

void evaluate(fuzzer_t& fuzzer, double reward, double scheduled_units) {
    double deep_edges_coverage = 0.0; // legacy placeholder

    // Calculate the reward and final score.
    double final_reward = reward + deep_edges_coverage;
    double final_score = 0.0;
    if (final_reward + scheduled_units > 0.0) {
        final_score = final_reward / (final_reward + scheduled_units);
    }

    fuzzer_last_rewards[fuzzer.label] = final_reward;
    fuzzer_scores[fuzzer.label] = final_score;
}

static void recompute_round_probabilities(const vector<fuzzer_t>& fuzzers,
                                          const map<uint32_t, double>& selected_fuzzers,
                                          double n_snapshot) {
    map<string, double> scheduled_units_by_label;
    for (const auto& it : selected_fuzzers) {
        scheduled_units_by_label[fuzzers[it.first].label] = it.second;
    }

    double sum_exp = 0.0;
    for (const auto& fuzzer : fuzzers) {
        const string& label = fuzzer.label;
        const bool selected_this_round = scheduled_units_by_label.count(label) > 0;

        if (fuzzer_effective_units.find(label) == fuzzer_effective_units.end()) {
            fuzzer_effective_units[label] = 0.0;
        }
        if (fuzzer_last_rewards.find(label) == fuzzer_last_rewards.end()) {
            fuzzer_last_rewards[label] = 0.0;
        }

        if (selected_this_round) {
            fuzzer_effective_units[label] = scheduled_units_by_label[label];
        }

        const double effective_units = fuzzer_effective_units[label];
        double q = Q_INIT;
        double u = U_INIT;
        if (effective_units > 0.0) {
            const double reward =
                fuzzer_cumulative_rewards.count(label) ? fuzzer_cumulative_rewards[label] : 0.0;
            if (reward + effective_units > 0.0) {
                q = reward / (reward + effective_units);
            }
            if (n_snapshot > 1.0) {
                u = sqrt(2.0 * log(n_snapshot) / effective_units);
            }
        }

        fuzzer_scores[label] = q;
        fuzzer_u[label] = u;

        const double score_with_exploration = fuzzer_scores[label] + u;
        if (isfinite(score_with_exploration)) {
            sum_exp += exp(score_with_exploration);
        }
    }

    if (sum_exp == 0.0) {
        return;
    }

    for (const auto& fuzzer : fuzzers) {
        const string& label = fuzzer.label;
        const double score_with_exploration = fuzzer_scores[label] + fuzzer_u[label];
        fuzzer_probabilities[label] = isfinite(score_with_exploration)
            ? exp(score_with_exploration) / sum_exp
            : 0.0;
    }
}

void update_global_record() {
}

void evaluate_all(map<uint32_t, double> selected_fuzzers,
                  vector<fuzzer_t> fuzzers,
                  vector<string> deep_function,
                  size_t round,
                  const map<uint32_t, std::string>& baseline_reports) {
    // C4 is evaluated against the round-start global fuzzing record M. M is
    // refreshed only after seed synchronization updates the global seed pool.
    fuzzer_sync_targets.clear();
    const std::unordered_set<std::string> seen_crashes_before_round = seen_crash_fingerprints_global;
    std::unordered_set<std::string> round_seen_crashes;

    vector<unsigned long> c4_baseline_counts = global_edge_frequency_counts;

    // Now evaluate each selected fuzzer with the round-start global edge counts.
    // Collect per-fuzzer metrics (c0..c4)
    struct FInfo { uint32_t idx; string label; double scheduled; vector<unsigned long> metrics; };
    vector<FInfo> finfos;
    for (auto& it : selected_fuzzers) {
        fuzzer_t selected_fuzzer = fuzzers[it.first];
        string local_seed_folder = selected_fuzzer.label + to_string(round);
        string report_name = local_seed_folder + ".report";
        string baseline_report;
        auto baseline_it = baseline_reports.find(it.first);
        if (baseline_it != baseline_reports.end()) {
            baseline_report = baseline_it->second;
        }
        parsed_report_metrics_t parsed = parse_report_metrics(report_name,
                                                             baseline_report,
                                                             selected_fuzzer.label,
                                                             deep_function,
                                                             seen_crashes_before_round,
                                                             &c4_baseline_counts);
        FInfo fi;
        fi.idx = it.first;
        fi.label = selected_fuzzer.label;
        fi.scheduled = it.second;
        fi.metrics = std::move(parsed.metrics);
        finfos.push_back(std::move(fi));
        round_seen_crashes.insert(parsed.crash_fingerprints.begin(), parsed.crash_fingerprints.end());
        fuzzer_sync_targets[selected_fuzzer.label] = std::move(parsed.metric_targets);
    }

    if (finfos.empty()) return;

    seen_crash_fingerprints_global.insert(round_seen_crashes.begin(), round_seen_crashes.end());

    // Final round evaluation uses the standard deviation based metric weights.
    // Qualitative equal-weight scoring is only used by monitor evaluation.
    bool fine_tuning = false;

    // compute stddev for each metric across fuzzers
    size_t k = 5; // c0..c4
    vector<double> means(k, 0.0);
    vector<double> stds(k, 0.0);
    size_t mcount = finfos.size();
    for (size_t i = 0; i < k; ++i) {
        double s = 0.0;
        for (const auto &fi : finfos) s += (double)fi.metrics[i];
        means[i] = s / (double)mcount;
    }
    for (size_t i = 0; i < k; ++i) {
        double ss = 0.0;
        for (const auto &fi : finfos) {
            double d = (double)fi.metrics[i] - means[i];
            ss += d * d;
        }
        stds[i] = sqrt(ss / (double)mcount);
    }

    // compute weights as proportion of stddevs
    double sum_std = 0.0;
    for (double v : stds) sum_std += v;
    vector<double> weights(k, fine_tuning ? 1.0 : (1.0 / (double)k));

    if (!fine_tuning && sum_std > 0.0) {
        for (size_t i = 0; i < k; ++i) weights[i] = stds[i] / sum_std;
    }

    double round_scheduled_units = 0.0;
    for (const auto& fi : finfos) {
        round_scheduled_units += fi.scheduled;
    }
    const double n_snapshot = N + round_scheduled_units;
    N = n_snapshot;

    // compute weighted reward per selected fuzzer and update their scores
    for (const auto &fi : finfos) {
        double weighted = 0.0;
        for (size_t i = 0; i < k; ++i) 
        // {
        //     double normalized = 0.0;
        //     if (maxs[i] > mins[i]) {
        //         normalized = ((double)fi.metrics[i] - mins[i]) / (maxs[i] - mins[i]);
        //     } else {
        //         normalized = 1.0; 
        //     }

        //     weighted += weights[i] * normalized;
        // }
            weighted += weights[i] * (double)fi.metrics[i];
        fuzzer_t selected_fuzzer = fuzzers[fi.idx];
        fuzzer_cumulative_rewards[selected_fuzzer.label] += weighted;
        evaluate(selected_fuzzer,
                 fuzzer_cumulative_rewards[selected_fuzzer.label],
                 fi.scheduled);
    }
    recompute_round_probabilities(fuzzers, selected_fuzzers, n_snapshot);
}

void reset_monitor_state() {
    monitor_seen_edges_global = seen_edges_global;
    monitor_seen_paths_global = seen_paths_global;
    monitor_seen_crash_fingerprints_global = seen_crash_fingerprints_global;
}

monitor_eval_result_t evaluate_monitor_window(const vector<monitor_eval_input_t>& inputs,
                                              const vector<string>& deep_function) {
    monitor_eval_result_t result;
    if (inputs.empty()) {
        return result;
    }

    vector<unsigned long> window_edge_counts;
    const std::unordered_set<unsigned long> seen_edges_before_window = monitor_seen_edges_global;
    const std::unordered_set<unsigned long> seen_paths_before_window = monitor_seen_paths_global;
    const std::unordered_set<std::string> seen_crashes_before_window =
        monitor_seen_crash_fingerprints_global;
    std::unordered_set<unsigned long> window_seen_edges;
    std::unordered_set<unsigned long> window_seen_paths;
    std::unordered_set<std::string> window_seen_crashes;

    for (const auto& input : inputs) {
        add_report_edge_counts(input.report_path, window_edge_counts);
    }

    // C4 is evaluated against the monitor-window-start historical counts. The
    // current monitor window is added only after the window has been evaluated.
    vector<unsigned long> c4_baseline_counts = global_edge_frequency_counts;

    struct MonitorInfo {
        string label;
        vector<unsigned long> metrics;
        std::unordered_set<unsigned long> covered_edges;
        std::unordered_set<unsigned long> covered_paths;
        std::unordered_set<std::string> crash_fingerprints;
    };
    vector<MonitorInfo> finfos;
    for (const auto& input : inputs) {
        parsed_report_metrics_t parsed = parse_report_metrics(input.report_path,
                                                             input.baseline_report_path,
                                                             input.label,
                                                             deep_function,
                                                             seen_crashes_before_window,
                                                             &c4_baseline_counts,
                                                             &seen_edges_before_window,
                                                             &seen_paths_before_window);
        MonitorInfo fi;
        fi.label = input.label;
        fi.metrics = std::move(parsed.metrics);
        fi.covered_edges = std::move(parsed.covered_edges);
        fi.covered_paths = std::move(parsed.covered_paths);
        fi.crash_fingerprints = std::move(parsed.crash_fingerprints);
        finfos.push_back(std::move(fi));
    }

    if (finfos.empty()) {
        return result;
    }

    for (const auto& fi : finfos) {
        window_seen_edges.insert(fi.covered_edges.begin(), fi.covered_edges.end());
        window_seen_paths.insert(fi.covered_paths.begin(), fi.covered_paths.end());
        window_seen_crashes.insert(fi.crash_fingerprints.begin(), fi.crash_fingerprints.end());
    }
    monitor_seen_edges_global.insert(window_seen_edges.begin(), window_seen_edges.end());
    monitor_seen_paths_global.insert(window_seen_paths.begin(), window_seen_paths.end());
    monitor_seen_crash_fingerprints_global.insert(window_seen_crashes.begin(), window_seen_crashes.end());

    for (const auto& fi : finfos) {
        double qualitative_reward = 0.0;
        for (size_t i = 0; i < fi.metrics.size(); ++i) {
            qualitative_reward += (double)fi.metrics[i];
        }
        result.rewards[fi.label] = qualitative_reward;
    }

    return result;
}
