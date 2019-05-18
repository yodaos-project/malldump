#ifndef __PTMALLOC_H
#define __PTMALLOC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ptmalloc_offset {
	size_t mallinfo;
	size_t mp_;
	size_t narenas;
};

int ptmalloc_injection(int pid, struct ptmalloc_offset *offset, int human);

#ifdef __cplusplus
}
#endif
#endif
