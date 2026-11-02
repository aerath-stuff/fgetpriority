// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#pragma once

#define MIN_APP_PROCESS_UID      10000
#define MIN_ISOLATED_PROCESS_UID 90000

static const int AID_USER_OFFSET = 100000;

/* (uid_t)-1 is unmappable; unlike an isolated UID, it cannot own tasks. */
#define HIDDEN_PRIORITY_UID (-1)

