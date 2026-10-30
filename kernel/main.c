
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

static uintptr_t kallsyms_lookup_name_fn = 0x0;
static __nocfi unsigned long __kallsyms_lookup_name(const char *name)
{
	return kallsyms_lookup_name_fn(name);
}

#ifdef CONFIG_MODULES
#define kernel_function_lookup(name) __kallsyms_lookup_name(#name)
#else
#define kernel_function_lookup(name) ({ 						\
	pr_info("kernel_function_lookup: %s addr: 0x%lx\n", #name, (uintptr_t)&name);	\
	(uintptr_t)&name; 								\
})
#endif

#include "arm64_branch_insn.h"
#include "routine.c"

static int __init fgetpriority_init(void)
{
	pr_info("init: Hello World!\n");

	getpriority_hook_init();
	return 0;
}

static void __exit fgetpriority_exit(void)
{
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
