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
#include "option.h"
#include "unilog.h"

#define CONFIG_FILE "ptmalloc_dump.conf"

static struct option opttab[] = {
	INIT_OPTION_BOOL("-D", "debug", false, ""),
	INIT_OPTION_INT("-p:", "pid", 0, ""),
	INIT_OPTION_STRING("-f:", "logfile", "/tmp/ptmalloc_dump.log", ""),
	INIT_OPTION_STRING("-I:", "mallinfo_offset", "0x86e30", ""),
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
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
		LOG_ERROR("PTRACE_SETREGS, %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int write_context(int pid, const struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
		LOG_ERROR("PTRACE_SETREGS, %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

#ifdef __x86_64__
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
	long data;

	// TODO: check return value of ptrace

	// set regs
	read_context(pid, &regs);
	regs.rsp -= 0x100;
	regs.rbp = regs.rsp;
	regs.rax = 0;
	regs.rdi = regs.rsp + sizeof(long) * 4;
	regs.rip = base + offset;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	write_context(pid, &regs);
	mallinfo_addr = regs.rdi;

	// set rip on stack
	data = regs.rsp + sizeof(long) * 2;
	ptrace(PTRACE_POKEDATA, pid, regs.rsp, (void *)data);

	// set int 3 on stack
	ptrace(PTRACE_POKEDATA, pid, regs.rsp + sizeof(long) * 2, (void *)0xcc);

	// continue
	data = ptrace(PTRACE_CONT, pid, NULL, NULL);
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

	// get result of mallinfo
	read_context(pid, &regs);
	for (int i = 0; i < 5; i++) {
		data = ptrace(PTRACE_PEEKDATA, pid, mallinfo_addr + i * 8, NULL);
		memcpy((char *)&mi + i * 8, &data, sizeof(data));
	}

	return mi;
}
#endif

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
