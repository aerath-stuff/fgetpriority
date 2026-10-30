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

#if defined(__GNUC__) && !defined(__clang__)
#define KEEP_SYMBOL_NO_TAIL __attribute__((used)) noinline __attribute__((optimize("no-optimize-sibling-calls")))
#else
#define KEEP_SYMBOL_NO_TAIL __attribute__((used)) noinline __attribute__((disable_tail_calls))
#endif

KEEP_SYMBOL_NO_TAIL struct user_struct *hook_find_user(kuid_t uid)
{
	kuid_t n_uid = uid;
	kuid_t dummy = { .val = 99999 };

	if (getpriority_should_swap(*(int *)&uid))
		n_uid = dummy;

	return hook_find_user(n_uid); // void
}
#undef KEEP_SYMBOL_NO_TAIL



static __init int getpriority_hook_init(void)
{


	return 0;
}

static int getpriority_hook_exit(void)
{


	return 0;
}
