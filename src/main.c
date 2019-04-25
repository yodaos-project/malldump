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

#define CONFIG_FILE "ptmalloc_dump.conf"

static struct option opttab[] = {
	INIT_OPTION_BOOL("-D", "debug", false, ""),
	INIT_OPTION_INT("-p:", "pid", 0, ""),
	INIT_OPTION_STRING("-f:", "logfile", "/tmp/ptmalloc_dump.log", ""),
	INIT_OPTION_STRING("-I:", "mallinfo_offset", "0x73ab8", "a113"),
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
	snprintf(cmd, 256, "cat /proc/%d/maps |grep 'libc-.*.so' |head -n1 |cut -d'-' -f1", pid);
	exec_shell(cmd, result, 256);

	char *endptr = NULL;
	return strtol(result, &endptr, 16);
}

static int attach_process(int pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		LOG_ERROR("PTRACE_ATTACH, %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int detach_process(int pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		LOG_ERROR("PTRACE_DETACH, %s\n", strerror(errno));
		return -1;
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
		LOG_ERROR("PTRACE_GETREGS, %s\n", strerror(errno));
		return -1;
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
		LOG_ERROR("PTRACE_SETREGS, %s\n", strerror(errno));
		return -1;
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
	         trap_count <= TRAP_COUNT_MAX);
	ptrace(PTRACE_POKEDATA, pid, trap_pc, (void *)trap_pc_text);

	// get result of mallinfo
	for (int i = 0; i < 5; i++) {
		data = ptrace(PTRACE_PEEKDATA, pid, mallinfo_addr + i * 8, NULL);
		memcpy((char *)&mi + i * 8, &data, sizeof(data));
	}

	return mi;
}

static int start_injection(int pid)
{
	struct user_regs_struct regs;
	struct mallinfo mi;

	attach_process(pid);
	waitpid(pid, NULL, 0);
	read_context(pid, &regs);

	long mallinfo_offset = strtol(
		find_option("mallinfo_offset", opttab)->value.s,
		NULL, 16);
	mi = inject_libc_mallinfo(pid, mallinfo_offset);
	LOG_INFO("arena: %d\n", mi.arena);
	LOG_INFO("ordblks: %d\n", mi.ordblks);
	LOG_INFO("smblks: %d\n", mi.smblks);
	LOG_INFO("hblks: %d\n", mi.hblks);
	LOG_INFO("hblkhd: %d\n", mi.hblkhd);
	LOG_INFO("usmblks: %d\n", mi.usmblks);
	LOG_INFO("fsmblks: %d\n", mi.fsmblks);
	LOG_INFO("uordblks: %d\n", mi.uordblks);
	LOG_INFO("fordblks: %d\n", mi.fordblks);
	LOG_INFO("keepcost: %d\n", mi.keepcost);

	write_context(pid, &regs);
	detach_process(pid);

	return 0;
}

int main(int argc, char *argv[])
{
	if (access(CONFIG_FILE, R_OK) == 0)
		assert(option_init_from_file(opttab, CONFIG_FILE) == 0);

	if (option_init_from_arg(opttab, argc, argv)) {
		LOG_ERROR("%s\n", option_errmsg());
		exit(EXIT_FAILURE);
	}

	if (find_option("debug", opttab)->value.b)
		unilog_set_level(UNILOG_DEBUG);
	else
		unilog_set_level(UNILOG_INFO);

	start_injection(find_option("pid", opttab)->value.i);

	return 0;
}
