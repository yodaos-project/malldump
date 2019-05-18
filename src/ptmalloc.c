#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <extlog.h>
#include "regs.h"
#include "sys.h"

#ifndef MALLINFO_OFFSET
#error "MALLINFO_OFFSET is not defined"
#endif

#ifndef MP__OFFSET
#error "MP__OFFSET is not defined"
#endif

#define PT_LEN sizeof(void *)
#define KILOBYTE 1024
#define MEGABYTE (1024 * 1024)

struct malloc_par {
	/* Tunable parameters */
	unsigned long trim_threshold;
	size_t top_pad;
	size_t mmap_threshold;
	size_t arena_test;
	size_t arena_max;

	/* ... */
};

static struct mallinfo inject_libc_mallinfo(int pid, long offset)
{
	/*
	 * 0x0 -> rip
	 * 0x8 -> 0x0
	 * 0x10 -> 0xcc
	 * 0x18 -> 0x0
	 * 0x20 -> mallinfo
	 */

	struct mallinfo mi;
	unsigned long mallinfo_addr = 0;
	unsigned long base = get_libc_base(pid);
	struct user_regs_struct regs;
	long trap_pc;
	long trap_pc_text;
	long trap_count;
	long data;

	// TODO: check return value of ptrace

	// set regs
	read_process_context(pid, &regs);
#ifdef __x86_64__
	SP(&regs) = ((SP(&regs) - 0x100) & ~0xf) + PT_LEN;
	BP(&regs) = SP(&regs);
	R0(&regs) = 0;
	DI(&regs) = SP(&regs) + PT_LEN * 4;
	mallinfo_addr = DI(&regs);
#elif defined __aarch64__ || defined __arm__
	SP(&regs) = (SP(&regs) - 0x100) & ~0xf;
	FP(&regs) = SP(&regs);
	R0(&regs) = SP(&regs) + PT_LEN * 4;
	RR(&regs) = SP(&regs) + PT_LEN * 4;
	mallinfo_addr = R0(&regs);
#endif

	// set trap
	trap_pc = PC(&regs);
	trap_pc_text = read_process_data(pid, (void *)trap_pc);
#ifdef __x86_64__
	write_process_data(pid, (void *)trap_pc, (void *)0xcc);
	write_process_data(pid, (void *)SP(&regs), (void *)trap_pc);
#elif defined __aarch64__ || defined __arm__
	write_process_data(pid, (void *)trap_pc, (void *)0xe7f000f0);
	LR(&regs) = trap_pc;
#endif

	PC(&regs) = base + offset;
	write_process_context(pid, &regs);

	// continue
	LOG_DEBUG("PC: %lx\n", PC(&regs));
	LOG_DEBUG("SP: %lx\n", SP(&regs));
	LOG_DEBUG("trap_pc: %lx\n", trap_pc);
	trap_count = 0;
	do {
		continue_process(pid);
		wait_process(pid);
		read_process_context(pid, &regs);
		LOG_DEBUG("PC: %lx\n", PC(&regs));
		LOG_DEBUG("SP: %lx\n", SP(&regs));

		trap_count++;
	} while (PC(&regs) - TRAP_INST_LEN != trap_pc &&
	         trap_count < TRAP_COUNT_MAX);
	write_process_data(pid, (void *)trap_pc, (void *)trap_pc_text);

	// get result of mallinfo
	for (int i = 0; i < sizeof(struct mallinfo) / PT_LEN; i++) {
		data = read_process_data(pid, (void *)mallinfo_addr + i * PT_LEN);
		memcpy((char *)&mi + i * PT_LEN, &data, sizeof(data));
	}

	return mi;
}

static struct malloc_par inject_libc_mp_(int pid, long offset)
{
	unsigned long base = get_libc_base(pid);
	unsigned long mp__addr = base + offset;
	struct malloc_par mp;
	long data;

	for (int i = 0; i < sizeof(struct malloc_par) / PT_LEN; i++) {
		data = read_process_data(pid, (void *)mp__addr + i * PT_LEN);
		memcpy((char *)&mp + i * PT_LEN, &data, sizeof(data));
	}

	return mp;
}

int ptmalloc_injection(int pid, long mallinfo_offset, long mp__offset, int human)
{
	struct user_regs_struct regs;
	char process_cmdline[256];
	struct mallinfo mi;
	struct malloc_par mp;

	attach_process(pid);
	wait_process(pid);
	read_process_context(pid, &regs);

	if (mallinfo_offset == 0)
		mallinfo_offset = MALLINFO_OFFSET;

	if (mp__offset == 0)
		mp__offset = MP__OFFSET;

	get_process_cmdline(pid, process_cmdline, sizeof(process_cmdline));
	mi = inject_libc_mallinfo(pid, mallinfo_offset);
	mp = inject_libc_mp_(pid, mp__offset);
	printf("process cmd:    %s\n", process_cmdline);
	printf("process pid:    %d\n", pid);
	if (human) {
		printf("total memory:   %.1fK\n", (double)mi.arena / KILOBYTE);
		printf("avail memory:   %.1fK\n",
		       (double)mi.fordblks / KILOBYTE);
		printf("used memory:    %.1fK\n",
		       (double)mi.uordblks / KILOBYTE);
		printf("used memory%%:   %.2f%%\n",
		       (double)mi.uordblks / mi.arena * 100);
		printf("free chunks:    %d\n", mi.ordblks);
		printf("fastbin chunks: %d\n", mi.smblks);
		printf("fastbin memory: %.1fK\n", (double)mi.fsmblks / KILOBYTE);
		printf("mmapped chunks: %d\n", mi.hblks);
		printf("mmapped memory: %.1fK\n", (double)mi.hblkhd / KILOBYTE);
		printf("trim threshold: %.1fK\n",
		       (double)mp.trim_threshold / KILOBYTE);
		printf("mmap threshold: %.1fK\n",
		       (double)mp.mmap_threshold / KILOBYTE);
	} else {
		printf("total memory:   %d\n", mi.arena);
		printf("avail memory:   %d\n", mi.fordblks);
		printf("used memory:    %d\n", mi.uordblks);
		printf("used memory%%:   %.2f%%\n",
		       (double)mi.uordblks / mi.arena * 100);
		printf("free chunks:    %d\n", mi.ordblks);
		printf("fastbin chunks: %d\n", mi.smblks);
		printf("fastbin memory: %d\n", mi.fsmblks);
		printf("mmapped chunks: %d\n", mi.hblks);
		printf("mmapped memory: %d\n", mi.hblkhd);
		printf("trim threshold: %lu\n", mp.trim_threshold);
		printf("mmap threshold: %lu\n", mp.mmap_threshold);
	}

	write_process_context(pid, &regs);
	detach_process(pid);

	return 0;
}
