#include <stddef.h>
#include <stdint.h>

/* Independent integer dot: every possible partial sum fits signed i64.
 * No floating conversion, Rust producer, or GPU implementation is reused. */
int c71_matrix_i16(const int16_t *restrict weights, const int16_t *restrict input,
                   int64_t *restrict output, size_t rows, size_t columns) {
    if (!weights || !input || !output || !rows || !columns
        || columns > INT64_MAX / (INT64_C(32768) * 32767)
        || rows > SIZE_MAX / columns)
        return 1;
    for (size_t k = 0; k < columns; ++k)
        if (input[k] == INT16_MIN) return 1;
    unsigned invalid = 0;
    for (size_t row = 0; row < rows; ++row) {
        int64_t sum = 0;
        for (size_t k = 0; k < columns; ++k) {
            int16_t value = weights[row * columns + k];
            invalid |= value == INT16_MIN;
            sum += (int64_t)value * input[k];
        }
        output[row] = sum;
    }
    return invalid != 0;
}

typedef struct {
    uint64_t limb[3];
} u192;

static u192 mul_u128_u64(uint64_t lo, uint64_t hi, uint64_t value) {
    __uint128_t low = (__uint128_t)lo * value;
    __uint128_t high = (__uint128_t)hi * value + (uint64_t)(low >> 64);
    u192 result = {{(uint64_t)low, (uint64_t)high, (uint64_t)(high >> 64)}};
    return result;
}

static int compare_u192(u192 left, u192 right) {
    for (int index = 2; index >= 0; --index) {
        if (left.limb[index] != right.limb[index])
            return left.limb[index] > right.limb[index] ? 1 : -1;
    }
    return 0;
}

/* Returns zero on success, otherwise the one-based failing lane. */
size_t c71_rms_batch(const int64_t *products, size_t count,
                     uint64_t numerator_lo, uint64_t numerator_hi,
                     uint64_t denominator_lo, uint64_t denominator_hi,
                     uint64_t multiplier, int16_t *outputs) {
    const uint64_t product_bound = UINT64_C(32767) * UINT64_C(32767);
    for (size_t index = 0; index < count; ++index) {
        int64_t product = products[index];
        if (product < -(int64_t)product_bound || product > (int64_t)product_bound)
            return index + 1;
        if (product == 0) {
            outputs[index] = 0;
            continue;
        }
        if (multiplier >= (UINT64_C(1) << 47))
            return index + 1;
        uint64_t magnitude_product = product < 0 ? (uint64_t)(-product) : (uint64_t)product;
        __uint128_t scaled = (__uint128_t)magnitude_product * multiplier;
        uint64_t magnitude = (uint64_t)(scaled >> 32);
        uint64_t remainder = (uint32_t)scaled;
        magnitude += remainder > (UINT64_C(1) << 31)
                     || (remainder == (UINT64_C(1) << 31) && (magnitude & 1));
        if (magnitude > 32767)
            return index + 1;

        uint64_t square = magnitude_product * magnitude_product;
        u192 left = mul_u128_u64(numerator_lo, numerator_hi, 4 * square);
        uint64_t odd = 2 * magnitude + 1;
        u192 right = mul_u128_u64(denominator_lo, denominator_hi, odd * odd);
        int comparison = compare_u192(left, right);
        magnitude += comparison > 0 || (comparison == 0 && (magnitude & 1));
        if (magnitude > 32767)
            return index + 1;
        outputs[index] = (int16_t)(product < 0 ? -(int64_t)magnitude : (int64_t)magnitude);
    }
    return 0;
}
