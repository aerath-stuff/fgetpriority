// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "routine.h"

static __always_inline bool getpriority_should_swap(int which, int who, const bool is_io)
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

	if (!is_io && which != PRIO_USER)
		return false;

	if (is_io && which != IOPRIO_WHO_USER)
		return false;

//	pr_info("ksu_getpriority: caller: %d paramms: %d / %d comm: %s \n", current_uid().val, which, who, current->comm);

//	pr_info("getpriority: uid: %d is set! \n", who);
	return true;
}

#if IS_ENABLED(CONFIG_KPROBES)
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

#define kp_is_registered(p) (!!((p)->addr))

static __always_inline struct pt_regs *sc_regs(struct pt_regs *regs)
{
	return (struct pt_regs *)regs->regs[0];
}

static int pre_arm64_setpriority(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *sc = sc_regs(regs);

	int which = sc->regs[0];
	int *p_who = (int *)&sc->regs[1];

	if (!!getpriority_should_swap(which, *p_who, false))
		*p_who = 99999;

	return 0;
}

static int pre_arm64_ioprio_set(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *sc = sc_regs(regs);

	int which = sc->regs[0];
	int *p_who = (int *)&sc->regs[1];

	if (!!getpriority_should_swap(which, *p_who, true))
		*p_who = 99999;

	return 0;
}

static int entry_arm64_getpriority(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *sc = sc_regs(regs);

	int which = sc->regs[0];
	int *p_who = (int *)&sc->regs[1];

	if (!!getpriority_should_swap(which, *p_who, false))
		sc->regs[1] = 99999;

	return 0;
}

static int entry_arm64_ioprio_get(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *sc = sc_regs(regs);

	int which = sc->regs[0];
	int *p_who = (int *)&sc->regs[1];

	if (!!getpriority_should_swap(which, *p_who, true))
		sc->regs[1] = 99999;

	return 0;
}

static int ret_dummy(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

#define kp_setter(suffix, name) { .symbol_name = "__arm64" #suffix "_sys_" #name, .pre_handler = pre_arm64_##name }
#define kp_setter_native(name) kp_setter(, name)

#define kp_getter(suffix, name) {						\
	.kp.symbol_name = "__arm64" #suffix "_sys_" #name,	\
	.entry_handler = entry_arm64_##name,				\
	.handler = ret_dummy,								\
	.maxactive = 128,									\
	.data_size = 0,										\
}
#define kp_getter_native(name) kp_getter(, name)

// native
static struct kprobe kp_arm64_setpriority    = kp_setter_native(setpriority);
static struct kprobe kp_arm64_ioprio_set     = kp_setter_native( ioprio_set);
static struct kretprobe kp_arm64_getpriority = kp_getter_native(getpriority);
static struct kretprobe kp_arm64_ioprio_get  = kp_getter_native( ioprio_get);

static __always_inline int register_kprobe_log(struct kprobe *kp, const char *name)
{
	int ret = register_kprobe(kp);
	pr_info("%s: register kprobe %s, ret: %d\n", __func__, name, ret);
	return ret;
}

static __always_inline int register_kretprobe_log(struct kretprobe *kp, const char *name)
{
	int ret = register_kretprobe(kp);
	pr_info("%s: register kretprobe %s, ret: %d\n", __func__, name, ret);
	return ret;
}

static __always_inline void unregister_kprobe_log(struct kprobe *kp, const char *name)
{
	if (!kp_is_registered(kp)) return;
	unregister_kprobe(kp);
	pr_info("%s: unregister kprobe %s\n", __func__, name);
}

static __always_inline void unregister_kretprobe_log(struct kretprobe *kp, const char *name)
{
	if (!kp_is_registered(&kp->kp)) return;
	unregister_kretprobe(kp);
	pr_info("%s: unregister kretprobe %s\n", __func__, name);
}

static __init int getpriority_hook_init(void)
{
	int ret;

	if ((ret = register_kprobe_log(&kp_arm64_setpriority, "setpriority"))  < 0) goto return_with;
	if ((ret = register_kprobe_log(&kp_arm64_ioprio_set, "ioprio_set")) < 0) goto f2;
	if ((ret = register_kretprobe_log(&kp_arm64_getpriority, "getpriority"))  < 0) goto f3;
	if ((ret = register_kretprobe_log(&kp_arm64_ioprio_get, "ioprio_get")) < 0) goto f4;

	goto return_with;

f4: unregister_kretprobe(&kp_arm64_getpriority);
f3: unregister_kprobe(&kp_arm64_ioprio_set);
f2: unregister_kprobe(&kp_arm64_setpriority);

return_with:
	return ret;
}

static int getpriority_hook_exit(void)
{
	unregister_kprobe_log(&kp_arm64_setpriority, "setpriority");
	unregister_kprobe_log(&kp_arm64_ioprio_set, "ioprio_set");
	unregister_kretprobe_log(&kp_arm64_getpriority, "getpriority");
	unregister_kretprobe_log(&kp_arm64_ioprio_get, "ioprio_get");

	pr_info("%s: exit OK\n", __func__);
	return 0;
}
#else // no kprobes
// dummy
static uintptr_t dummy = 0x0;

// native
#define __AARCH64_setpriority	140
#define __AARCH64_getpriority	141
#define __AARCH64_ioprio_set	30
#define __AARCH64_ioprio_get	31

static uintptr_t aarch64_setpriority __read_mostly = 0x0;
static uintptr_t aarch64_getpriority __read_mostly = 0x0;
static uintptr_t aarch64_ioprio_get __read_mostly = 0x0;
static uintptr_t aarch64_ioprio_set __read_mostly = 0x0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
asmlinkage __nocfi long hook_aarch64_setpriority(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, false))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_setpriority) *)aarch64_setpriority)(regs);

	extern typeof(hook_aarch64_setpriority) __arm64_sys_setpriority;
	return __arm64_sys_setpriority(regs);
}

asmlinkage __nocfi long hook_aarch64_getpriority(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, false))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_getpriority) *)aarch64_getpriority)(regs);

	extern typeof(hook_aarch64_getpriority) __arm64_sys_getpriority;
	return __arm64_sys_getpriority(regs);
}
asmlinkage __nocfi long hook_aarch64_ioprio_get(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, true))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_ioprio_get) *)aarch64_ioprio_get)(regs);

	extern typeof(hook_aarch64_ioprio_get) __arm64_sys_ioprio_get;
	return __arm64_sys_ioprio_get(regs);
}

asmlinkage __nocfi long hook_aarch64_ioprio_set(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, true))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_ioprio_set) *)aarch64_ioprio_set)(regs);

	extern typeof(hook_aarch64_ioprio_set) __arm64_sys_ioprio_set;
	return __arm64_sys_ioprio_set(regs);
}

#else	/* < 4.19 */
asmlinkage __nocfi long hook_aarch64_setpriority(int which, int who, int niceval)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, false))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_setpriority) *)aarch64_setpriority)(which, new_who, niceval);

	return sys_setpriority(which, new_who, niceval);
}

asmlinkage __nocfi long hook_aarch64_getpriority(int which, int who)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, false))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_getpriority) *)aarch64_getpriority)(which, new_who);

	return sys_getpriority(which, new_who);
}

asmlinkage __nocfi long hook_aarch64_ioprio_get(int which, int who)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, true))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_ioprio_get) *)aarch64_ioprio_get)(which, new_who);

	return sys_ioprio_get(which, new_who);
}

asmlinkage __nocfi long hook_aarch64_ioprio_set(int which, int who, int ioprio)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, true))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_aarch64_ioprio_set) *)aarch64_ioprio_set)(which, new_who, ioprio);

	return sys_ioprio_set(which, new_who, ioprio);
}
#endif	/* < 4.19 */

#define patch_syscall_slot(storage, sys_nr, hook) ({					\
	uintptr_t *table = (uintptr_t *)native_sct;					\
	storage = table[sys_nr];							\
	int ret = write_to_readonly_slot((uintptr_t)&table[sys_nr], (uintptr_t)hook);	\
	pr_info("%s: patching %s: ret: %d \n", __func__, #sys_nr, ret);			\
	ret;										\
})

// compat
#define __ARMEABI_getpriority	96
#define __ARMEABI_setpriority	97
#define __ARMEABI_ioprio_set	314
#define __ARMEABI_ioprio_get	315

static uintptr_t armeabi_setpriority __read_mostly = 0x0;
static uintptr_t armeabi_getpriority __read_mostly = 0x0;
static uintptr_t armeabi_ioprio_get __read_mostly = 0x0;
static uintptr_t armeabi_ioprio_set __read_mostly = 0x0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
asmlinkage __nocfi long hook_armeabi_getpriority(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, false))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_getpriority) *)armeabi_getpriority)(regs);

	extern typeof(hook_armeabi_getpriority) __arm64_sys_getpriority;
	return __arm64_sys_getpriority(regs);
}

asmlinkage __nocfi long hook_armeabi_setpriority(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, false))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_setpriority) *)armeabi_setpriority)(regs);

	extern typeof(hook_armeabi_setpriority) __arm64_sys_setpriority;
	return __arm64_sys_setpriority(regs);
}

asmlinkage __nocfi long hook_armeabi_ioprio_get(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, true))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_ioprio_get) *)armeabi_ioprio_get)(regs);

	extern typeof(hook_armeabi_getpriority) __arm64_sys_ioprio_get;
	return __arm64_sys_ioprio_get(regs);
}

asmlinkage __nocfi long hook_armeabi_ioprio_set(const struct pt_regs *regs)
{
	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!getpriority_should_swap(which, *p_who, true))
		*p_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_ioprio_set) *)armeabi_ioprio_set)(regs);

	extern typeof(hook_armeabi_getpriority) __arm64_sys_ioprio_set;
	return __arm64_sys_ioprio_set(regs);
}

#else	/* < 4.19 */

asmlinkage __nocfi long hook_armeabi_getpriority(int which, int who)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, false))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_getpriority) *)armeabi_getpriority)(which, new_who);

	return sys_getpriority(which, new_who);
}

asmlinkage __nocfi long hook_armeabi_setpriority(int which, int who, int niceval)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, false))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_setpriority) *)armeabi_setpriority)(which, new_who, niceval);

	return sys_setpriority(which, new_who, niceval);
}

asmlinkage __nocfi long hook_armeabi_ioprio_get(int which, int who)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, true))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_ioprio_get) *)armeabi_ioprio_get)(which, new_who);

	return sys_ioprio_get(which, new_who);
}

asmlinkage __nocfi long hook_armeabi_ioprio_set(int which, int who, int ioprio)
{
	int new_who = who;
	if (!!getpriority_should_swap(which, who, true))
		new_who = 99999;

	if (is_module)
		return ((typeof(hook_armeabi_ioprio_set) *)armeabi_ioprio_set)(which, new_who, ioprio);

	return sys_ioprio_set(which, new_who, ioprio);
}
#endif	/* < 4.19 */

#define patch_syscall_slot_compat(storage, sys_nr, hook) ({				\
	uintptr_t *table = (uintptr_t *)compat_sct;					\
	storage = table[sys_nr];							\
	int ret = write_to_readonly_slot((uintptr_t)&table[sys_nr], (uintptr_t)hook);	\
	pr_info("%s: patching %s: ret: %d \n", __func__, #sys_nr, ret);			\
	ret;										\
})

static __init int getpriority_hook_init(void)
{
	if (!!patch_syscall_slot(aarch64_setpriority, __AARCH64_setpriority, hook_aarch64_setpriority))
		return -EINTR;

	if (!!patch_syscall_slot(aarch64_getpriority, __AARCH64_getpriority, hook_aarch64_getpriority))
		return -EINTR;

	if (!!patch_syscall_slot(aarch64_ioprio_set, __AARCH64_ioprio_set, hook_aarch64_ioprio_set))
		return -EINTR;

	if (!!patch_syscall_slot(aarch64_ioprio_get, __AARCH64_ioprio_get, hook_aarch64_ioprio_get))
		return -EINTR;

	if (!compat_hook_enabled)
		return 0;

	if (!!patch_syscall_slot_compat(armeabi_setpriority, __ARMEABI_setpriority, hook_armeabi_setpriority))
		return -EINTR;

	if (!!patch_syscall_slot_compat(armeabi_getpriority, __ARMEABI_getpriority, hook_armeabi_getpriority))
		return -EINTR;

	if (!!patch_syscall_slot_compat(armeabi_ioprio_set, __ARMEABI_ioprio_set, hook_armeabi_ioprio_set))
		return -EINTR;

	if (!!patch_syscall_slot_compat(armeabi_ioprio_get, __ARMEABI_ioprio_get, hook_armeabi_ioprio_get))
		return -EINTR;

	return 0;
}

static int getpriority_hook_exit(void)
{
	patch_syscall_slot(dummy, __AARCH64_ioprio_get, aarch64_ioprio_get);
	patch_syscall_slot(dummy, __AARCH64_ioprio_set, aarch64_ioprio_set);
	patch_syscall_slot(dummy, __AARCH64_getpriority, aarch64_getpriority);
	patch_syscall_slot(dummy, __AARCH64_setpriority, aarch64_setpriority);

	if (compat_hook_enabled) {
		patch_syscall_slot_compat(dummy, __ARMEABI_ioprio_get, armeabi_ioprio_get);
		patch_syscall_slot_compat(dummy, __ARMEABI_ioprio_set, armeabi_ioprio_set);
		patch_syscall_slot_compat(dummy, __ARMEABI_getpriority, armeabi_getpriority);
		patch_syscall_slot_compat(dummy, __ARMEABI_setpriority, armeabi_setpriority);
	}

	return 0;
}
#endif
