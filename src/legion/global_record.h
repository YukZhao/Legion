#ifndef GLOBAL_RECORD_H
#define GLOBAL_RECORD_H

#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>
#include "fs_compat.h"
#include "fuzzer_wrapper.h"

using namespace std;

// Global variables
extern double N; // Sum of all effective scheduled_units
extern std::map<std::string, double> fuzzer_scores;
extern std::map<std::string, double> fuzzer_u;
extern std::map<std::string, double> fuzzer_probabilities;
typedef struct sync_metric_targets_t {
    std::unordered_set<unsigned long> c0_edges;
    std::unordered_set<uint32_t> c1_paths;
    std::unordered_set<std::string> c2_crashes;
    std::unordered_set<unsigned long> c3_deep_edges;
    std::unordered_set<unsigned long> c4_low_freq_edges;
} sync_metric_targets_t;
typedef struct monitor_eval_input_t {
    std::string label;
    std::string report_path;
    std::string baseline_report_path;
} monitor_eval_input_t;
typedef struct monitor_eval_result_t {
    std::map<std::string, double> rewards;
} monitor_eval_result_t;
extern std::map<std::string, sync_metric_targets_t> fuzzer_sync_targets;

void evaluate(fuzzer_t& fuzzer, double reward, double scheduled_units);

void update_global_record();

void initialize_global_seed_baseline(const std::string& report_path);
void refresh_global_record_from_report(const std::string& report_path);

void evaluate_all(map<uint32_t, double> selected_fuzzers,
                  vector<fuzzer_t> fuzzers,
                  vector<string> deep_function,
                  size_t round,
                  const map<uint32_t, std::string>& baseline_reports);
void reset_monitor_state();
monitor_eval_result_t evaluate_monitor_window(const vector<monitor_eval_input_t>& inputs,
                                              const vector<string>& deep_function);

#endif
