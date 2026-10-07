/* Offline pilot only: exact symmetric i16 -> binary64 dyadic weights.
 * Compile without fast-math. The caller owns distinct input/output spans.
 * A nonzero return invalidates the entire output; no partial use is allowed. */
#include <math.h>
#include <stddef.h>
#include <stdint.h>

int c71_pilot_convert(const int16_t *input, double *output, size_t count, int exponent) {
    if (!input || !output || !count || exponent < -128 || exponent > 128)
        return 1;
    const double scale = ldexp(1.0, exponent);
    unsigned invalid = 0;
    for (size_t i = 0; i < count; ++i) {
        const int16_t value = input[i];
        invalid |= value == INT16_MIN;
        output[i] = (double)value * scale;
    }
    return invalid != 0;
}
