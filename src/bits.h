#pragma once

#include <stdint.h>

static inline unsigned
bit_get(uint32_t x, unsigned bit)
{
    return (x >> bit) & 1;
}

static inline uint32_t
bits_mask(unsigned nbits)
{
    if (nbits == 32)
        return ~0;
    return (1 << nbits) - 1;
}

static inline uint32_t
bits_get(uint32_t x, unsigned ub, unsigned lb)
{
    return (x >> lb) & bits_mask(ub - lb + 1);
}

static inline uint32_t
bits_clr(uint32_t x, unsigned ub, unsigned lb)
{
    uint32_t mask = bits_mask(ub - lb + 1);
    return x & ~(mask << lb);
}

static inline uint32_t
bits_set(uint32_t x, unsigned ub, unsigned lb, uint32_t v)
{
    return bits_clr(x, ub, lb) | (v << lb);
}
