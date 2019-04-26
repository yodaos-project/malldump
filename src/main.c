#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include "option.h"
#include "unilog.h"

#ifdef __x86_64__
#define R0(registers) ((registers)->rax)
#define DI(registers) ((registers)->rdi)
#define BP(registers) ((registers)->rbp)
#define SP(registers) ((registers)->rsp)
#define PC(registers) ((registers)->rip)
#define TRAP_INST_LEN 1
#elif defined __aarch64__
#define R0(registers) ((registers)->regs[0])
#define R8(registers) ((registers)->regs[8])
#define SP(registers) ((registers)->sp)
#define PC(registers) ((registers)->pc)
#define FP(registers) ((registers)->regs[29])
#define LR(registers) ((registers)->regs[30])
#define TRAP_INST_LEN 0 // ill inst
#endif
#define TRAP_COUNT_MAX 3

#ifndef MALLINFO_OFFSET
#define MALLINFO_OFFSET -1
#endif

#define CONFIG_FILE "malldump.conf"

static struct option opttab[] = {
	INIT_OPTION_BOOL("-D", "debug", false, ""),
	INIT_OPTION_BOOL("-h", "human", false, ""),
	INIT_OPTION_INT("-p:", "pid", 0, ""),
	INIT_OPTION_STRING("-f:", "logfile", "/tmp/malldump.log", ""),
	INIT_OPTION_STRING("-I:", "mallinfo_offset", "", ""),
	INIT_OPTION_NONE(),
};

static int exec_shell(const char *cmd, char *result, size_t result_size)
{
	int pid;
	int fd[2];

	if (pipe(fd) == -1)
		return -1;

	pid = fork();
	if (pid == -1) {
		close(fd[0]);
		close(fd[1]);
		return -1;
	}

	if (pid == 0) {
		close(fd[0]);
		dup2(fd[1], STDOUT_FILENO);
		close(fd[1]);
		execlp("sh", "sh", "-c", cmd, NULL);
		exit(0);
	} else {
		close(fd[1]);
		int nr = 0;
		int offset = 0;
		while ((nr = read(fd[0], result + offset,
		                  result_size - offset - 1)) > 0) {
			offset += nr;
		}
		waitpid(pid, NULL, 0);
		close(fd[0]);
	}

	return 0;
}

static unsigned long long get_libc_base(int pid)
{
	char cmd[256], result[256];
	snprintf(cmd, 256, "cat /proc/%d/maps |grep 'libc-.*.so'"
	         " |head -n1 |cut -d'-' -f1", pid);
	exec_shell(cmd, result, 256);

	char *endptr = NULL;
	return strtol(result, &endptr, 16);
}

static int attach_process(int pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		fprintf(stderr, "PTRACE_ATTACH, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}

static int detach_process(int pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		fprintf(stderr, "PTRACE_DETACH, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}

static int read_context(int pid, struct user_regs_struct *regs)
{
	int rc;

#ifdef __x86_64__
	rc = ptrace(PTRACE_GETREGS, pid, NULL, regs);
#elif defined __aarch64__
	struct iovec iovec;
	iovec.iov_base = regs;
	iovec.iov_len = sizeof(*regs);
	rc = ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iovec);
#endif

	if (rc == -1) {
		fprintf(stderr, "PTRACE_GETREGS, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return 0;
}

static int write_context(int pid, struct user_regs_struct *regs)
{
	int rc;

#ifdef __x86_64__
	rc = ptrace(PTRACE_SETREGS, pid, NULL, regs);
#elif defined __aarch64__
	struct iovec iovec;
	iovec.iov_base = regs;
	iovec.iov_len = sizeof(*regs);
	rc = ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iovec);
#endif

	if (rc == -1) {
		fprintf(stderr, "PTRACE_SETREGS, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return 0;
}

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
	unsigned long long mallinfo_addr = 0;
	unsigned long long base = get_libc_base(pid);
	struct user_regs_struct regs;
	long trap_pc;
	long trap_pc_text;
	long trap_count;
	long data;

	// TODO: check return value of ptrace

	// set regs
	read_context(pid, &regs);
	SP(&regs) -= 0x100;
#ifdef __x86_64__
	BP(&regs) = SP(&regs);
	R0(&regs) = 0;
	DI(&regs) = SP(&regs) + sizeof(long) * 4;
	mallinfo_addr = DI(&regs);
#elif defined __aarch64__
	FP(&regs) = SP(&regs);
	R0(&regs) = SP(&regs) + sizeof(long) * 4;
	R8(&regs) = SP(&regs) + sizeof(long) * 4;
	mallinfo_addr = R0(&regs);
#endif

	// set trap
	trap_pc = PC(&regs);
	trap_pc_text = ptrace(PTRACE_PEEKDATA, pid, trap_pc, NULL);
#ifdef __x86_64__
	ptrace(PTRACE_POKEDATA, pid, trap_pc, (void *)0xcc);
	ptrace(PTRACE_POKEDATA, pid, SP(&regs), (void *)trap_pc);
#elif defined __aarch64__
	ptrace(PTRACE_POKEDATA, pid, trap_pc, (void *)0xe7f000f0);
	LR(&regs) = trap_pc;
#endif

	PC(&regs) = base + offset;
	write_context(pid, &regs);

	// continue
	LOG_DEBUG("PC: %llx\n", PC(&regs));
	LOG_DEBUG("SP: %llx\n", SP(&regs));
	LOG_DEBUG("trap_pc: %llx\n", trap_pc);
	trap_count = 0;
	do {
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			LOG_DEBUG("exited, status=%d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			LOG_DEBUG("killed by signal %d\n", WTERMSIG(status));
		} else if (WIFSTOPPED(status)) {
			LOG_DEBUG("stopped by signal %d\n", WSTOPSIG(status));
		} else if (WIFCONTINUED(status)) {
			LOG_DEBUG("continued\n");
		}
		read_context(pid, &regs);
		LOG_DEBUG("PC: %llx\n", PC(&regs));
		LOG_DEBUG("SP: %llx\n", SP(&regs));

		trap_count++;
	} while (PC(&regs) - TRAP_INST_LEN != trap_pc &&
	         trap_count < TRAP_COUNT_MAX);
	ptrace(PTRACE_POKEDATA, pid, trap_pc, (void *)trap_pc_text);

	// get result of mallinfo
	for (int i = 0; i < 5; i++) {
		data = ptrace(PTRACE_PEEKDATA, pid, mallinfo_addr + i * 8, NULL);
		memcpy((char *)&mi + i * 8, &data, sizeof(data));
	}

	return mi;
}

static int is_process_exist(int pid)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "/proc/%d/", pid);
	if (access(buf, R_OK) == 0)
		return 1;
	else
		return 0;
}

static int get_process_cmdline(int pid, char *buf, size_t size)
{
	// TODO: error check

	snprintf(buf, size, "/proc/%d/cmdline", pid);

	int fd = open(buf, O_RDONLY);
	int nr, offset = 0;
	while ((nr = read(fd, buf + offset, size - offset)) > 0)
		offset += nr;
	close(fd);

	if (offset > strlen(buf))
		buf[strlen(buf)] = ' ';

	return 0;
}

static int start_injection(int pid)
{
	struct user_regs_struct regs;
	struct mallinfo mi;
	long mallinfo_offset;
	char process_cmdline[256];

	attach_process(pid);
	waitpid(pid, NULL, 0);
	read_context(pid, &regs);

	if (MALLINFO_OFFSET != -1)
		mallinfo_offset = MALLINFO_OFFSET;
	if (strlen(find_option("mallinfo_offset", opttab)->value.s)) {
		mallinfo_offset = strtol(
			find_option("mallinfo_offset", opttab)->value.s,
			NULL, 16);
	}

	mi = inject_libc_mallinfo(pid, mallinfo_offset);
	get_process_cmdline(pid, process_cmdline, sizeof(process_cmdline));
	printf("process cmd:    %s\n", process_cmdline);
	printf("process pid:    %d\n", pid);
	if (find_option("human", opttab)->value.b) {
		printf("total memory:   %.1fK\n", (double)mi.arena / 1024);
		printf("avail memory:   %.1fK\n", (double)mi.fordblks / 1024);
		printf("used memory:    %.1fK\n", (double)mi.uordblks / 1024);
		printf("used memory%%:  %.2f%%\n",
		       (double)mi.uordblks / mi.arena * 100);
		printf("free chunks:    %d\n", mi.ordblks);
		printf("fastbin chunks: %d\n", mi.smblks);
		printf("fastbin memory: %.1fK\n", (double)mi.fsmblks / 1024);
		printf("mmapped chunks: %d\n", mi.hblks);
		printf("mmapped memory: %.1fK\n", (double)mi.hblkhd / 1024);
	} else {
		printf("total memory:   %d\n", mi.arena);
		printf("avail memory:   %d\n", mi.fordblks);
		printf("used memory:    %d\n", mi.uordblks);
		printf("used memory%%:  %.2f%%\n",
		       (double)mi.uordblks / mi.arena * 100);
		printf("free chunks:    %d\n", mi.ordblks);
		printf("fastbin chunks: %d\n", mi.smblks);
		printf("fastbin memory: %d\n", mi.fsmblks);
		printf("mmapped chunks: %d\n", mi.hblks);
		printf("mmapped memory: %d\n", mi.hblkhd);
	}

	write_context(pid, &regs);
	detach_process(pid);

	return 0;
}

int main(int argc, char *argv[])
{
	if (access(CONFIG_FILE, R_OK) == 0)
		assert(option_init_from_file(opttab, CONFIG_FILE) == 0);

	if (option_init_from_arg(opttab, argc, argv)) {
		fprintf(stderr, "%s\n", option_errmsg());
		exit(EXIT_FAILURE);
	}

	if (find_option("debug", opttab)->value.b)
		unilog_set_level(UNILOG_DEBUG);
	else
		unilog_set_level(UNILOG_INFO);

	int pid = find_option("pid", opttab)->value.i;
	if (!is_process_exist(pid)) {
		fprintf(stderr, "Process(%d) not exist, exit ...\n", pid);
		exit(EXIT_FAILURE);
	}
	start_injection(pid);

	option_fini(opttab);
	return 0;
}
