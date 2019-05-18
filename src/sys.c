#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <elf.h>
#include <extlog.h>

int exec_shell(const char *cmd, char *result, size_t result_size)
{
	pid_t pid;
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

unsigned long long get_libc_base(pid_t pid)
{
	char cmd[256], result[256];
	snprintf(cmd, 256, "cat /proc/%d/maps |grep 'libc-.*.so'"
	         " |head -n1 |cut -d'-' -f1", pid);
	exec_shell(cmd, result, 256);

	char *pos;
	if ((pos=strchr(result, '\n')) != NULL)
		*pos = '\0';

	char *endptr = NULL;
	return strtoll(result, &endptr, 16);
}

int is_file_exist(const char *path)
{
	if (access(path, R_OK) == 0)
		return 1;
	else
		return 0;
}

int is_process_exist(pid_t pid)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "/proc/%d/", pid);
	if (access(buf, R_OK) == 0)
		return 1;
	else
		return 0;
}

int get_process_cmdline(pid_t pid, char *buf, size_t size)
{
	// TODO: error check

	snprintf(buf, size, "/proc/%d/cmdline", pid);

	int fd = open(buf, O_RDONLY);
	int nr, offset = 0;
	while ((nr = read(fd, buf + offset, size - offset)) > 0)
		offset += nr;
	close(fd);

	// FIXME: dangerous code?
	while (offset > strlen(buf))
		buf[strlen(buf)] = ' ';

	return 0;
}

int get_process_nr_thread(pid_t pid)
{
	char cmd[256], result[256];
	snprintf(cmd, 256, "ls /proc/%d/task |wc -l", pid);
	exec_shell(cmd, result, 256);

	char *pos;
	if ((pos=strchr(result, '\n')) != NULL)
		*pos = '\0';

	return strtol(result, NULL, 10);
}

int attach_process(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		fprintf(stderr, "PTRACE_ATTACH, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}

int detach_process(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		fprintf(stderr, "PTRACE_DETACH, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}

int continue_process(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		fprintf(stderr, "PTRACE_CONT, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}

int wait_process(pid_t pid)
{
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

	return status;
}

long read_process_context(pid_t pid, struct user_regs_struct *regs)
{
	long rc;

#ifdef __x86_64__
	rc = ptrace(PTRACE_GETREGS, pid, NULL, regs);
#elif defined __aarch64__ || defined __arm__
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

long write_process_context(pid_t pid, struct user_regs_struct *regs)
{
	long rc;

#ifdef __x86_64__
	rc = ptrace(PTRACE_SETREGS, pid, NULL, regs);
#elif defined __aarch64__ || defined __arm__
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

long read_process_data(pid_t pid, void *addr)
{
	return ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
}

long write_process_data(pid_t pid, void *addr, void *data)
{
	return ptrace(PTRACE_POKEDATA, pid, addr, data);
}
