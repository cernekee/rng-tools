/*
 * rngd_signals.c -- Signal handling
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

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "rngd.h"
#include "exits.h"
#include "rngd_signals.h"
#include "rngd_threads.h"


/* Signals, set to non-zero when a signal is received */
volatile sig_atomic_t gotsigterm = 0; /* SIGTERM/SIGINT */
volatile sig_atomic_t gotsigusr1 = 0; /* SIGUSR1 */
volatile sig_atomic_t gotsigalrm = 0; /* SIGALRM */

/* Only one SIGARLM user at a time... */
static pthread_mutex_t sigalrm_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t sigalrm_owner;
static unsigned int sigalrm_installed = 0;

/* Signal handlers */
static void sigterm_handler(int sig)
{
	gotsigterm = 128 | sig;
}

static void sigusr1_handler(int sig)
{
	gotsigusr1 = 1;
}

static void sigalrm_handler(int sig)
{
	gotsigalrm = 1;
}

/* Enable SIGALRM */
int enable_sigalrm(unsigned int seconds)
{
	sigset_t sigs;
	struct sigaction action;
	int result = 0;

	pthread_mutex_lock(&sigalrm_mutex);
	if (sigalrm_installed == 0 ||
			pthread_equal(pthread_self(), sigalrm_owner)) {
		sigemptyset(&action.sa_mask);
		action.sa_flags = 0;
		action.sa_handler = sigalrm_handler;
		if (sigaction(SIGALRM, &action, NULL) < 0) {
			message_strerr(LOG_ERR, errno,
				"unable to install signal handler for SIGARLM");
			result = -1;
		} else {
			sigemptyset(&sigs);
			sigaddset(&sigs, SIGALRM);
			pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
		
			sigalrm_installed = 1;
			sigalrm_owner = pthread_self();
			gotsigalrm = 0;
			alarm(seconds);
		}
	} else {
		message(LOG_ERR,
			"PROGRAM FAILURE DETECTED: two threads trying to use SIGARLM at the same time");
		result = -1;
	}
	pthread_mutex_unlock(&sigalrm_mutex);
	return result;
}

/* Disable SIGALRM */
int disable_sigalrm(void)
{
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);

	pthread_mutex_lock(&sigalrm_mutex);
	if (sigalrm_installed != 0 && 
			pthread_equal(pthread_self(), sigalrm_owner)) {
		alarm(0);
		sigalrm_installed = 0;
	}
	pthread_mutex_unlock(&sigalrm_mutex);
	return 0;
}

/* Init signal handlers */
void init_sighandlers(void)
{
	sigset_t sigs;
	struct sigaction action;

	/* Initialize signal mask */
	sigemptyset(&sigs);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	action.sa_handler = sigterm_handler;

	/* Handle SIGTERM and SIGINT the same way */
	if (sigaction(SIGTERM, &action, NULL) < 0) {
		message_strerr(LOG_ERR, errno,
			"unable to install signal handler for SIGTERM");
		die(EXIT_OSERR);
	}
	if (sigaction(SIGINT, &action, NULL) < 0) {
	        message_strerr(LOG_ERR, errno,
			"unable to install signal handler for SIGINT");
	        die(EXIT_OSERR);
	}

	/* Handle SIGUSR1 in a more friendly way */
	action.sa_flags = SA_RESTART;
	action.sa_handler = sigusr1_handler;
	if (sigaction(SIGUSR1, &action, NULL) < 0) {
	        message_strerr(LOG_ERR, errno,
			"unable to install signal handler for SIGUSR1");
	        die(EXIT_OSERR);
	}

	gotsigterm = gotsigusr1 = 0;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGUSR1);
	pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
}
