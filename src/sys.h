#ifndef __SYS_H
#define __SYS_H

#include <sys/user.h>

#define PT_LEN sizeof(void *)

#ifdef __cplusplus
extern "C" {
#endif

int exec_shell(const char *cmd, char *result, size_t result_size);
size_t get_libc_base(pid_t pid);

int is_file_exist(const char *path);

int is_process_exist(pid_t pid);
int get_process_cmdline(pid_t pid, char *buf, size_t size);
int get_process_nr_thread(pid_t pid);

int attach_process(pid_t pid);
int detach_process(pid_t pid);
int continue_process(pid_t pid);
int wait_process(pid_t pid);

int read_process_context(pid_t pid, struct user_regs_struct *regs);
int write_process_context(pid_t pid, struct user_regs_struct *regs);
int read_process_data(pid_t pid, size_t addr, void *out, size_t out_size);
int write_process_data(pid_t pid, size_t addr, void *data, size_t size);

#ifdef __cplusplus
}
#endif
#endif
