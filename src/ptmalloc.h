#ifndef __PTMALLOC_H
#define __PTMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

int ptmalloc_injection(int pid, long mallinfo_offset, long mp__offset, int human);

#ifdef __cplusplus
}
#endif
#endif
