#ifndef TIMING_H
#define TIMING_H

#include <windows.h>

double get_elapsed_time(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER frequency);

#endif
