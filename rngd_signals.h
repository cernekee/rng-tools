/*
 * rngd_signals.h -- Signal handling
 *
 * Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef RNGD_SIGNALS__H
#define RNGD_SIGNALS__H

#include "rng-tools-config.h"

#include "rngd.h"

#include <unistd.h>
#include <stdint.h>
#include <signal.h>

/* Signals, set to non-zero when a signal is received */
extern volatile sig_atomic_t gotsigterm; /* SIGTERM/SIGINT */
extern volatile sig_atomic_t gotsigusr1; /* SIGUSR1 */
extern volatile sig_atomic_t gotsigalrm; /* SIGALRM */

/* Setup signal handling */
extern void init_sighandlers( void );

/* SIGALRM: Enable handling for this thread,
 * and schedules an alarm().
 * 
 * Only one thread can handle SIGALRM at a time
 *
 * Returns zero on success */
extern int enable_sigalrm( unsigned int seconds );

/* SIGALMR: Disable handling for this thread (default).
 * Always return zero */
extern int disable_sigalrm( void );

#endif /* RNGD_SIGNALS__H */
