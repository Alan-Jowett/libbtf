// Generated from twomaps.o

#pragma once

typedef unsigned long long __uint64_t;

typedef __uint64_t uint64_t;

struct ctx;

struct {
  int (*type)[2];
  int (*key_size)[4];
  int (*value_size)[8];
  int (*max_entries)[2];
} map2;

struct {
  int (*type)[2];
  int *key;
  uint64_t *value;
  int (*max_entries)[1];
} map1;

