/*
 * Piotr Dobiech 316625
 */

#pragma once

#define println(format, ...) printf(format "\n" __VA_OPT__(, ) __VA_ARGS__)

#define eprintln(format, ...)                                                  \
    fprintf(stderr, format "\n" __VA_OPT__(, ) __VA_ARGS__)

// #define DEBUG
#ifdef DEBUG
#define debug(...) println(__VA_ARGS__)
#else
#define debug(...)
#endif
