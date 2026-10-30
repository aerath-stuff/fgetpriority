
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include "kernel.h"

#if !defined(__aarch64__)
static_assert(1 == 0, "ARM64 only!");
#endif

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "fgetpriority: " fmt
#endif

#ifdef TIF_SECCOMP
#define is_seccomp_enabled() test_thread_flag(TIF_SECCOMP)
#else
#define is_seccomp_enabled() (!!current->seccomp.mode)
#endif

#ifdef MODULE
#define is_module true
#else
#define is_module false
#endif

#ifdef MODULE
static uintptr_t kallsyms_lookup_name_fn = 0x0;
static __nocfi unsigned long __kallsyms_lookup_name(const char *name)
{
	return ((typeof (__kallsyms_lookup_name) *)kallsyms_lookup_name_fn)(name);
}
module_param(kallsyms_lookup_name_fn, ulong, 0000);
MODULE_PARM_DESC(kallsyms_lookup_name_fn, "kallsyms_lookup_name symaddr");
#define kallsyms_lookup_name __kallsyms_lookup_name

static inline __nocfi int __aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt)
{
	typeof(__aarch64_insn_patch_text) *fn = kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!fn)
		return -ENOENT;

	return fn(addrs, insns, cnt);
}
#define aarch64_insn_patch_text __aarch64_insn_patch_text

static inline __nocfi u32 __aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr, enum aarch64_insn_branch_type type)
{
	typeof(__aarch64_insn_gen_branch_imm) *fn = kallsyms_lookup_name("aarch64_insn_gen_branch_imm");
	if (!fn)
		return -ENOENT;

	return fn(pc, addr, type);
}
#define aarch64_insn_gen_branch_imm __aarch64_insn_gen_branch_imm
#endif

#ifdef CONFIG_MODULES
#define kernel_function_lookup(name) kallsyms_lookup_name(#name)
#else
#define kernel_function_lookup(name) ({ 						\
	pr_info("kernel_function_lookup: %s addr: 0x%lx\n", #name, (uintptr_t)&name);	\
	(uintptr_t)&name; 								\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) // probe_kernel_read
__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.2.21/source/mm/maccess.c#L27
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif

#include "arm64_branch_insn.h"
#include "routine.c"

static int __init fgetpriority_init(void)
{
	pr_info("init: Hello World!\n");

#ifdef MODULE
	char buf[KSYM_SYMBOL_LEN];
	sprint_symbol_no_offset(buf, kallsyms_lookup_name_fn);
	char ksym_c[] = "kallsyms_lookup_name";
	if (!!strcmp(buf, ksym_c)) {
		pr_info("init: wrong symbol!? %s found!\n", buf);
		return -EAGAIN;
	}
	pr_info("kallsyms_lookup_name: 0x%lx\n", kallsyms_lookup_name_fn);
#endif

	int ret = getpriority_hook_init();
	pr_info("init: ret: %d\n", ret);

	return 0;
}

static void __exit fgetpriority_exit(void)
{
	// TODO: unload routine
	__builtin_trap();
	__builtin_unreachable();
}

module_init(fgetpriority_init);
module_exit(fgetpriority_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xx");
MODULE_DESCRIPTION("fgetpriority");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
