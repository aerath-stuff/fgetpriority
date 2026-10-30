// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define MIN_APP_PROCESS_UID      10000
#define MIN_ISOLATED_PROCESS_UID 90000

static const int AID_USER_OFFSET = 100000;

static __always_inline bool getpriority_should_swap(int who)
{
	if (unlikely(!is_seccomp_enabled()))
		return false;

	// only filter appuid calls
	int cuid = current_uid().val;
	if (unlikely(cuid < MIN_APP_PROCESS_UID || who < MIN_APP_PROCESS_UID))
		return false;

	if (unlikely(cuid >= AID_USER_OFFSET))
		cuid %= AID_USER_OFFSET;

	// convert all isolated processes to appuids
	if (unlikely(cuid >= MIN_ISOLATED_PROCESS_UID))
	{
		struct user_namespace *ns = current_cred()->user_ns;
		if (ns && ns != &init_user_ns)
		{
			kuid_t host_kuid = make_kuid(ns, 0);
			if (uid_valid(host_kuid))
				cuid = from_kuid(&init_user_ns, host_kuid);
		}
	}

	if (unlikely(who >= MIN_ISOLATED_PROCESS_UID))
	{
		struct user_namespace *ns = current_cred()->user_ns;
		if (ns && ns != &init_user_ns)
		{
			kuid_t host_kuid = make_kuid(ns, 0);
			if (uid_valid(host_kuid))
				who = from_kuid(&init_user_ns, host_kuid);
		}
	}

	if (unlikely(who >= AID_USER_OFFSET))
	    who %= AID_USER_OFFSET;

	if (likely(cuid == who))
		return false;

	return true;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winfinite-recursion"

#if defined(__GNUC__) && !defined(__clang__)
#define KEEP_SYMBOL_NO_TAIL __attribute__((used)) noinline __attribute__((optimize("no-optimize-sibling-calls")))
#else
#define KEEP_SYMBOL_NO_TAIL __attribute__((used)) noinline __attribute__((disable_tail_calls))
#endif

KEEP_SYMBOL_NO_TAIL struct user_struct *gphook_find_user(kuid_t uid)
{
	kuid_t n_uid = uid;
	kuid_t dummy = { .val = 99999 };

	if (getpriority_should_swap(*(int *)&uid))
		n_uid = dummy;

	return gphook_find_user(n_uid); // void
}

#pragma GCC diagnostic pop
#undef KEEP_SYMBOL_NO_TAIL

#define estimate_sz	(128 * 4)

#define self_patch_hook(hook_fn, tgt) ({					\
	uintptr_t hook_p = kernel_function_lookup(hook_fn);			\
	int ret = arm64_b_or_bl_patch(hook_p, estimate_sz, hook_p, tgt);	\
	pr_info("patch_hook: %s ret: %d \n", #hook_fn, ret);			\
	ret;									\
})

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define syscall_lookup(name) kallsyms_lookup_retry("__arm64_" name)
#else
#define syscall_lookup(name) kallsyms_lookup_retry(name)
#endif

static __init int getpriority_hook_init(void)
{
	uintptr_t symbol_addr = kallsyms_lookup_name("find_user");
	if (!symbol_addr)
		return -ENOENT;

	int ret = self_patch_hook(gphook_find_user, symbol_addr);
	if (ret)
		return ret;

	// now patch callsites
	uintptr_t callsite = syscall_lookup("sys_getpriority");
	if (!callsite)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(callsite, estimate_sz, symbol_addr, (uintptr_t)&gphook_find_user);
	pr_info("%s: ret: %d \n"__func__, ret);

	callsite = syscall_lookup("sys_setpriority");
	if (!callsite)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(callsite, estimate_sz, symbol_addr, (uintptr_t)&gphook_find_user);
	pr_info("%s: ret: %d \n"__func__, ret);

	callsite = syscall_lookup("sys_setpriority");
	if (!callsite)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(callsite, estimate_sz, symbol_addr, (uintptr_t)&gphook_find_user);
	pr_info("%s: ret: %d \n"__func__, ret);

	callsite = syscall_lookup("sys_setpriority");
	if (!callsite)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(callsite, estimate_sz, symbol_addr, (uintptr_t)&gphook_find_user);
	pr_info("%s: ret: %d \n"__func__, ret);

	return 0;
}

static int getpriority_hook_exit(void)
{
	// TODO: unload routine
	return 0;
}
