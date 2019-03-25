#include <stdint.h>

#define BITS_PER_LONG (64)

#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif

#define L1_CACHE_SHIFT		(6)
#define L1_CACHE_BYTES		(1 << L1_CACHE_SHIFT)

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#define VA_BITS			(39)
#define PAGE_OFFSET		(uint64_t) (0xffffffffffffffff << (VA_BITS - 1))

#define KERNEL_PTR (PAGE_OFFSET)
#define KERNEL_START (PAGE_OFFSET + KERNEL_OFFSET)

typedef uint32_t kuid_t;
typedef uint32_t kgid_t;
typedef uint32_t atomic_t;
typedef uint32_t spinlock_t;
typedef unsigned int rwlock_t;
