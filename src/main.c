#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include <extopt.h>
#include <extlog.h>
#include "sys.h"

#ifdef __x86_64__
#define R0(registers) ((registers)->rax)
#define DI(registers) ((registers)->rdi)
#define BP(registers) ((registers)->rbp)
#define SP(registers) ((registers)->rsp)
#define PC(registers) ((registers)->rip)
#define TRAP_INST_LEN 1
#elif defined __aarch64__
#define R0(registers) ((registers)->regs[0])
#define RR(registers) ((registers)->regs[8])
#define FP(registers) ((registers)->regs[29])
#define LR(registers) ((registers)->regs[30])
#define SP(registers) ((registers)->sp)
#define PC(registers) ((registers)->pc)
#define TRAP_INST_LEN 0 // ill inst
#elif defined __arm__
#define user_regs_struct user_regs
#define R0(registers) ((registers)->uregs[0])
#define RR(registers) ((registers)->uregs[3])
#define FP(registers) ((registers)->uregs[11])
#define LR(registers) ((registers)->uregs[14])
#define SP(registers) ((registers)->uregs[13])
#define PC(registers) ((registers)->uregs[15])
#define TRAP_INST_LEN 0 // ill inst
#endif
#define TRAP_COUNT_MAX 3

#ifndef MALLINFO_OFFSET
#error "MALLINFO_OFFSET is not defined"
#endif

#ifndef MP__OFFSET
#error "MP__OFFSET is not defined"
#endif

#define PT_LEN sizeof(void *)
#define KILOBYTE 1024
#define MEGABYTE (1024 * 1024)

#define CONFIG_FILE "malldump.conf"

struct malloc_par {
	/* Tunable parameters */
	unsigned long trim_threshold;
	size_t top_pad;
	size_t mmap_threshold;
	size_t arena_test;
	size_t arena_max;

	/* ... */
};

// TODO: implement ptmalloc
static struct opt opttab[] = {
	INIT_OPT_BOOL("-h", "help", false, "print this usage"),
	INIT_OPT_BOOL("-D", "debug", false, "debug mode [defaut: false]"),

	INIT_OPT_STRING("-t", "type", "ptmalloc",
	                   "type of malloc [default: ptmalloc]"),
	INIT_OPT_INT("-p:", "pid", 0, "pid of the target process"),

// http://gcc.gnu.org/onlinedocs/cpp/Stringification.html
#define MALLINFO_DESC(OFFSET) "offset of mallinfo [default: " #OFFSET "]"
#define MALLINFO_DESC2(OFFSET) MALLINFO_DESC(OFFSET)
	INIT_OPT_INT("-I:", "mallinfo_offset", 0,
	                MALLINFO_DESC2(MALLINFO_OFFSET)),
#define MP__DESC(OFFSET) "offset of mp_ [default: " #OFFSET "]"
#define MP__DESC2(OFFSET) MP__DESC(OFFSET)
	INIT_OPT_INT("-P:", "mp__offset", 0, MP__DESC2(MP__OFFSET)),

	INIT_OPT_BOOL("-H", "human", false,
	                 "display size of memory in"
	                 " human mode [default: false]"),
	INIT_OPT_NONE(),
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

static int start_injection(int pid)
{
	struct user_regs_struct regs;
	char process_cmdline[256];
	struct mallinfo mi;
	long mallinfo_offset;
	struct malloc_par mp;
	long mp__offset;

	attach_process(pid);
	wait_process(pid);
	read_process_context(pid, &regs);

	if (opt_int(find_opt("mallinfo_offset", opttab)))
		mallinfo_offset = opt_int(find_opt("mallinfo_offset", opttab));
	else
		mallinfo_offset = MALLINFO_OFFSET;

	if (opt_int(find_opt("mp__offset", opttab)))
		mp__offset = opt_int(find_opt("mp__offset", opttab));
	else
		mp__offset = MP__OFFSET;

	get_process_cmdline(pid, process_cmdline, sizeof(process_cmdline));
	mi = inject_libc_mallinfo(pid, mallinfo_offset);
	mp = inject_libc_mp_(pid, mp__offset);
	printf("process cmd:    %s\n", process_cmdline);
	printf("process pid:    %d\n", pid);
	if (opt_bool(find_opt("human", opttab))) {
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

int main(int argc, char *argv[])
{
	if (is_file_exist(CONFIG_FILE))
		assert(opt_init_from_file(opttab, CONFIG_FILE) == 0);

	if (opt_init_from_arg(opttab, argc, argv)) {
		fprintf(stderr, "%s\n", opt_errmsg());
		exit(EXIT_FAILURE);
	}

	if (opt_bool(find_opt("help", opttab))) {
		opt_usage(opttab);
		exit(1);
	}

	if (opt_bool(find_opt("debug", opttab)))
		log_set_level(LOG_LV_DEBUG);
	else
		log_set_level(LOG_LV_INFO);

	int pid = opt_int(find_opt("pid", opttab));
	if (!is_process_exist(pid)) {
		fprintf(stderr, "Process(%d) not exist, exit ...\n", pid);
		exit(EXIT_FAILURE);
	}
	start_injection(pid);

	opt_fini(opttab);
	return 0;
}
