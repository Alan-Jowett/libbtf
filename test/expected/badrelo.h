typedef unsigned long long __uint64_t;

struct bpf_map;

struct ctx;

typedef __uint64_t uint64_t;

struct {
  int (*type)[2];
  int *key;
  int (*value)[0];
  int (*max_entries)[1];
} map;

