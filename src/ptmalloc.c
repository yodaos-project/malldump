#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <extlog.h>
#include "regs.h"
#include "sys.h"
#include "ptmalloc.h"

#ifndef MALLINFO_OFFSET
#error "MALLINFO_OFFSET is not defined"
#endif

#ifndef MP__OFFSET
#error "MP__OFFSET is not defined"
#endif

#ifndef NARENAS_OFFSET
#error "NARENAS_OFFSET is not defined"
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

static int
read_process_data_at_offset(int pid, size_t offset, void *out, size_t out_size)
{
	unsigned long base = get_libc_base(pid);
	unsigned long addr = base + offset;
	long data;

	for (int i = 0; i < out_size / PT_LEN; i++) {
		data = read_process_data(pid, (void *)addr + i * PT_LEN);
		memcpy(out + i * PT_LEN, &data, sizeof(data));
	}

	return 0;
}

static struct mallinfo inject_libc_mallinfo(int pid, size_t offset)
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

int ptmalloc_injection(int pid, struct ptmalloc_offset *offset, int human)
{
	struct user_regs_struct regs;
	char process_cmdline[256] = {0};
	int process_nr_thread;
	struct mallinfo mi;
	struct malloc_par mp_;
	size_t narenas;

	attach_process(pid);
	wait_process(pid);
	read_process_context(pid, &regs);

	if (offset->mallinfo == 0)
		offset->mallinfo = MALLINFO_OFFSET;

	if (offset->mp_ == 0)
		offset->mp_ = MP__OFFSET;

	if (offset->narenas == 0)
		offset->narenas = NARENAS_OFFSET;

	get_process_cmdline(pid, process_cmdline, sizeof(process_cmdline));
	process_nr_thread = get_process_nr_thread(pid);
	mi = inject_libc_mallinfo(pid, offset->mallinfo);
	read_process_data_at_offset(pid, offset->mp_, &mp_, sizeof(mp_));
	read_process_data_at_offset(pid, offset->narenas,
	                            &narenas, sizeof(narenas));

	printf("Process cmd:    %s\n", process_cmdline);
	printf("Process pid:    %d\n", pid);
	printf("Threads:        %d\n", process_nr_thread);
	printf("Arenas:         %lu\n", narenas);
	if (human) {
		printf("Total memory:   %.1fK\n", (double)mi.arena / KILOBYTE);
		printf("Avail memory:   %.1fK\n",
		       (double)mi.fordblks / KILOBYTE);
		printf("Used memory:    %.1fK\n",
		       (double)mi.uordblks / KILOBYTE);
		printf("Used memory%%:   %.2f%%\n",
		       (double)mi.uordblks / mi.arena * 100);
		printf("Free chunks:    %d\n", mi.ordblks);
		printf("Fastbin chunks: %d\n", mi.smblks);
		printf("Fastbin memory: %.1fK\n", (double)mi.fsmblks / KILOBYTE);
		printf("Mmapped chunks: %d\n", mi.hblks);
		printf("Mmapped memory: %.1fK\n", (double)mi.hblkhd / KILOBYTE);
		printf("Trim threshold: %.1fK\n",
		       (double)mp_.trim_threshold / KILOBYTE);
		printf("Mmap threshold: %.1fK\n",
		       (double)mp_.mmap_threshold / KILOBYTE);
	} else {
		printf("Total memory:   %d\n", mi.arena);
		printf("Avail memory:   %d\n", mi.fordblks);
		printf("Used memory:    %d\n", mi.uordblks);
		printf("Used memory%%:   %.2f%%\n",
		       (double)mi.uordblks / mi.arena * 100);
		printf("Free chunks:    %d\n", mi.ordblks);
		printf("Fastbin chunks: %d\n", mi.smblks);
		printf("Fastbin memory: %d\n", mi.fsmblks);
		printf("Mmapped chunks: %d\n", mi.hblks);
		printf("Mmapped memory: %d\n", mi.hblkhd);
		printf("Trim threshold: %lu\n", mp_.trim_threshold);
		printf("Mmap threshold: %lu\n", mp_.mmap_threshold);
	}

	write_process_context(pid, &regs);
	detach_process(pid);

	return 0;
}
