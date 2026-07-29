// trace-pc-guard-cb.cc
#include <stdint.h>
#include <stdio.h>
#include <sanitizer/coverage_interface.h>
//#include "hash_set.h"
#include <stdlib.h>
#include <string.h>
#include "murmur3.h"
#include <string>
#include <dlfcn.h>

using namespace std;

extern "C" void __sanitizer_symbolize_pc(void *pc, const char *fmt,
                                          char *out_buf, size_t out_buf_size)
    __attribute__((weak));


uint32_t* random_mark_for_tracing_jue;
string* function_name_for_tracing_jue;
size_t tracing_array_size_jue;
static bool symbolize_edges_jue = false;


uint32_t seed;

extern "C" void legion_set_symbolize_edges(int enabled) {
  symbolize_edges_jue = (enabled != 0);
}

extern "C" void legion_reset_trace_state() {
  if (random_mark_for_tracing_jue == nullptr || function_name_for_tracing_jue == nullptr) {
    return;
  }

  memset(random_mark_for_tracing_jue, 0, sizeof(uint32_t) * (tracing_array_size_jue + 1));
  for (size_t i = 0; i <= tracing_array_size_jue; ++i) {
    function_name_for_tracing_jue[i].clear();
  }
}



// This callback is inserted by the compiler as a module constructor
// into every DSO. 'start' and 'stop' correspond to the
// beginning and end of the section with the guards for the entire
// binary (executable or DSO). The callback will be called at least
// once per DSO and may be called multiple times with the same parameters.
extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
                                                    uint32_t *stop) {
  static uint64_t N;  // Counter for the guards.
  if (start == stop || *start) return;  // Initialize only once.
  printf("INIT: %p %p\n", start, stop);
  for (uint32_t *x = start; x < stop; x++)
    *x = ++N;  // Guards should start from 1.
  //printf("%lu edges in total for the binary.\n", N);
  random_mark_for_tracing_jue = new uint32_t[N+1]();
  function_name_for_tracing_jue = new string[N+1];


  tracing_array_size_jue = N; 
}

// This callback is inserted by the compiler on every edge in the
// control flow (some optimizations apply).
// Typically, the compiler will emit the code like this:
//    if(*guard)
//      __sanitizer_cov_trace_pc_guard(guard);
// But for large functions it will emit a simple call:
//    __sanitizer_cov_trace_pc_guard(guard);
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  if (!*guard) return;  // Duplicate the guard check.
  if (random_mark_for_tracing_jue == nullptr || *guard > tracing_array_size_jue) return;
  // If you set *guard to 0 this code will not be called again for this edge.
  // Now you can get the PC and do whatever you want:
  //   store it somewhere or symbolize it and print right away.
  // The values of `*guard` are as you set them in
  // __sanitizer_cov_trace_pc_guard_init and so you can make them consecutive
  // and use them to dereference an array or a bit vector.
  if (symbolize_edges_jue && __sanitizer_symbolize_pc != nullptr &&
      function_name_for_tracing_jue != nullptr &&
      random_mark_for_tracing_jue[*guard] == 0)
  {
      void *PC = __builtin_return_address(0);
      char PcDescr[1024];
  // This function is a part of the sanitizer run-time.
  // To use it, link with AddressSanitizer or other sanitizer.
      __sanitizer_symbolize_pc(PC, "%p %F %L", PcDescr, sizeof(PcDescr));
      //printf("PC %s", PcDescr);
      char* token = strtok(PcDescr, " ");
      token = strtok(NULL, " ");
      token = strtok(NULL, " ");
      if (token != nullptr) {
        char* name = strtok(token, "<");
        if (name != nullptr) {
          name = strtok(name, "(");
        }
        if (name != nullptr) {
          function_name_for_tracing_jue[*guard] = name;
        }
      }
      //printf(" %s\n", name);
  }
  
  //void *PC = __builtin_return_address(0);
  //char PcDescr[1024];
  // This function is a part of the sanitizer run-time.
  // To use it, link with AddressSanitizer or other sanitizer.
  // __sanitizer_symbolize_pc(PC, "%p %F %L", PcDescr, sizeof(PcDescr));
  //printf("guard: %p %x PC %s\n", guard, *guard, PcDescr);
  //printf("%u\n", *guard);
  random_mark_for_tracing_jue[*guard]++;
  
//  printf("before hash: %u %u", seed, *guard);

  seed = murmur3_hash(*guard, seed);

//  printf("after hash: %u\n", seed);
  
}
