#ifndef __REGS_H
#define __REGS_H

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
#define R0(registers) ((registers)->uregs[0])
#define RR(registers) ((registers)->uregs[3])
#define FP(registers) ((registers)->uregs[11])
#define LR(registers) ((registers)->uregs[14])
#define SP(registers) ((registers)->uregs[13])
#define PC(registers) ((registers)->uregs[15])
#define TRAP_INST_LEN 0 // ill inst
#endif
#define TRAP_COUNT_MAX 3

#endif
