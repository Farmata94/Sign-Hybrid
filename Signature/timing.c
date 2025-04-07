#include "timing.h"

double get_elapsed_time(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER frequency) {
    return (double)(end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
}
