/*
 * WARNING: Do *NOT* ever include this file, only for internal use!
 */
#ifndef _NFCT_BITOPS_H_
#define _NFCT_BITOPS_H_

static inline void set_bit(int nr, u_int32_t *addr)
{
	addr[nr >> 5] |= (1UL << (nr & 31));
}

static inline void unset_bit(int nr, u_int32_t *addr)
{
	addr[nr >> 5] &= ~(1UL << (nr & 31));
}

static inline void set_bit_u16(int nr, u_int16_t *addr)
{
	addr[nr >> 4] |= (1UL << (nr & 15));
}

static inline void unset_bit_u16(int nr, u_int16_t *addr)
{
	addr[nr >> 4] &= ~(1UL << (nr & 15));
}

static inline int test_bit(int nr, const u_int32_t *addr)
{
	return ((1UL << (nr & 31)) & (addr[nr >> 5])) != 0;
}

#endif
