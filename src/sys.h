#ifndef __SYS_H
#define __SYS_H

#include <sys/user.h>

#ifdef __cplusplus
extern "C" {
#endif

int exec_shell(const char *cmd, char *result, size_t result_size);
unsigned long long get_libc_base(pid_t pid);

int is_file_exist(const char *path);

int is_process_exist(pid_t pid);
int get_process_cmdline(pid_t pid, char *buf, size_t size);

int attach_process(pid_t pid);
int detach_process(pid_t pid);
int continue_process(pid_t pid);
int wait_process(pid_t pid);

long read_process_context(pid_t pid, struct user_regs_struct *regs);
long write_process_context(pid_t pid, struct user_regs_struct *regs);
long read_process_data(pid_t pid, void *addr);
long write_process_data(pid_t pid, void *addr, void *data);

#ifdef __cplusplus
}
#endif
#endif
