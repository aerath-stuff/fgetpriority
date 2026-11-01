
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

static uintptr_t native_sct = 0x0;
static uintptr_t compat_sct = 0x0;

static bool compat_hook_enabled = true;

#ifdef MODULE
#define is_module true
#else
#define is_module false
#endif

#include "vmap_patch.h"
#include "routine.c"

#ifdef MODULE
#if !IS_ENABLED(CONFIG_KPROBES)
static unsigned long native_sct_param = 0x0;
module_param(native_sct_param, ulong, 0000);
MODULE_PARM_DESC(native_sct_param, "sys_call_table symaddr");

static unsigned long compat_sct_param = 0x0;
module_param(compat_sct_param, ulong, 0000);
MODULE_PARM_DESC(compat_sct_param, "sys_call_table symaddr");
#endif

static struct kobject *mod_kobj_parent_backup = nullptr;
#endif

static int __init fgetpriority_init(void)
{
	pr_info("init: Hello World!\n");

#ifdef MODULE
#if !IS_ENABLED(CONFIG_KPROBES)
	native_sct = (uintptr_t)native_sct_param;
	if (!native_sct)
		return -EAGAIN;

	compat_sct = (uintptr_t)compat_sct_param;
	if (!compat_sct) {
		pr_info("init: compat_sys_call_table not supplied, will skip compat hooks\n");
		compat_hook_enabled = false;
	}

	char buf[KSYM_SYMBOL_LEN];
	sprint_symbol_no_offset(buf, native_sct);
	char ksym_n[] = "sys_call_table";
	if (!!strcmp(buf, ksym_n)) {
		pr_info("init: wrong symbol!? %s found!\n", buf);
		return -EAGAIN;
	}
	pr_info("init: %s: 0x%lx \n", buf, native_sct);

	if (!compat_hook_enabled)
		goto skip_compat;

	sprint_symbol_no_offset(buf, compat_sct);
	char ksym_c[] = "compat_sys_call_table";
	if (!!strcmp(buf, ksym_c)) {
		pr_info("init: wrong symbol!? %s found! will skip compat hooks!\n", buf);
		compat_hook_enabled = false;
	}
	pr_info("init: %s: 0x%lx \n", buf, compat_sct);
skip_compat:;
#endif

	mod_kobj_parent_backup = THIS_MODULE->mkobj.kobj.parent;
	kobject_del(&THIS_MODULE->mkobj.kobj);

#else /* ! MODULE */
#if !IS_ENABLED(CONFIG_KPROBES)
	native_sct = (uintptr_t)sys_call_table;
	pr_info("init: sys_call_table: 0x%lx \n", native_sct);

#ifdef CONFIG_COMPAT
	#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	extern const void *compat_sys_call_table[];
	#endif
	compat_sct = (uintptr_t)compat_sys_call_table;
	pr_info("init: compat_sys_call_table: 0x%lx \n", compat_sct);
#else
	compat_hook_enabled = false;
	pr_info("init: compat_sys_call_table will be skipped!\n");
#endif // CONFIG_COMPAT
#endif // kernel 5.11-
#endif /* ! MODULE */

// debug, print sct
//	print_sct();

	int ret = getpriority_hook_init();
	if (ret)
		panic("patching failed: %d\n", ret);

	pr_info("init: done!\n");
	return 0;
}

static int lkm_unload(void *unused)
{
	int ret = getpriority_hook_exit();
	if (ret)
		panic("patching failed: %d\n", ret);

	pr_info("exit: ok\n");
	return 0;
}

static void __exit fgetpriority_exit(void)
{
#ifndef MODULE
	__builtin_trap();
	__builtin_unreachable();
#else
	int ret = kobject_add(&THIS_MODULE->mkobj.kobj, mod_kobj_parent_backup, "%s", THIS_MODULE->name);
	pr_info("kobject_add ret: %d\n", ret);
	if (ret)
		panic("kobj add failed!\n");

	lkm_unload(nullptr);
#endif
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
