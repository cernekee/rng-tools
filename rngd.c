/*
 * rngd.c -- Random Number Generator daemon
 *
 * rngd reads data from a hardware random number generator, verifies it
 * looks like random data, and adds it to /dev/random's entropy store.
 * 
 * In theory, this should allow you to read very quickly from
 * /dev/random; rngd also adds bytes to the entropy store periodically
 * when it's full, which makes predicting the entropy store's contents
 * harder.
 *
 * Copyright (C) 2001 Philipp Rumpf
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

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "stats.h"
#include "rngd_threads.h"
#include "rngd_entsource.h"
#include "rngd_linux.h"

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

#define STR(x) #x
#define PROGNAME "rngd"

/*
 * Globals
 */

/* Statistics */
struct rng_stats rng_stats;

/* Background/daemon mode */
pid_t masterprocess;			/* PID of the master process */
int am_daemon;				/* Nonzero if we went daemon */
int exitstatus = EXIT_SUCCESS;		/* Exit status on SIGTERM */
static FILE *daemon_lockfp = NULL;	/* Lockfile file pointer */
static int daemon_lockfd;		/* Lockfile file descriptior */

/* Signals */
volatile int gotsigterm = 0;		/* Received a TERM signal */
static volatile int gotsigusr1 = 0;	/* Received a USR1 signal */

/* Command line arguments and processing */
const char *argp_program_version = 
	PROGNAME " " VERSION "\n"
	"Copyright (c) 2001 by Philipp Rumpf\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
error_t argp_err_exit_status = EXIT_USAGE;

static char doc[] =
	"Check and feed random data from hardware device to kernel entropy pool.\n";

#define ARGP_RNGD_CMDLINE_TRNG 0x81
	
static struct argp_option options[] = {
	{ "foreground",	'f', 0, 0, "Do not fork and become a daemon" },

	{ "background", 'b', 0, 0, "Become a daemon (default)" },

	{ "random-device", 'o', "file", 0,
	  "Kernel device used for entropy output (default: " DEVRANDOM ")" },

	{ "rng-device", 'r', "file", 0,
	  "Entropy source (default: " DEVHWRANDOM ")" },

	{ "random-step", 's', "n", 0,
	  "Number of bytes written to random-device at a time (default: 64), 8 <= n <= " STR(FIPS_RNG_BUFFER_SIZE) ", n must be even" },

	{ "fill-watermark", 'W', "n", 0,
	  "Do not stop feeding entropy to random-device until at least n bits of entropy are available in the pool (default: 2048), 0 <= n <= 4096" },

	{ "timeout", 't', "n", 0,
	  "Interval written to random-device when the entropy pool is full, in seconds (default: 60)" },

	{ "pidfile", 'p', "file", 0,
	  "Path to file to write PID to in daemon mode (default: " PIDFILE ")" },

	{ "rng-entropy", 'H', "n", 0,
	  "Entropy per bit of the hardware RNG (default: 1.0), 0 < n <= 1.0" },

	{ "rng-buffers", 'B', "n", 0,
	  "Number of buffers (default: 3),  0 < n <= " STR(MAX_RNG_BUFFERS) },

	{ "trng", ARGP_RNGD_CMDLINE_TRNG, "name", 0,
	  "Load known-good defaults for a given TRNG.  Use --trng=help to get a list of known TRNGs" },

	{ 0 },
};
static struct arguments default_arguments = {
	.rng_name	= DEVHWRANDOM,
	.random_name	= DEVRANDOM,
	.pidfile_name	= PIDFILE,
	.poll_timeout	= 60,
	.random_step	= 64,
	.fill_watermark = 2048,
	.daemon		= 1,
	.rng_entropy	= 1.0,
	.rng_buffers	= 3,
};
struct arguments *arguments = &default_arguments;

/* Predefined known-good values for TRNGs */
struct trng_params {
	char *tag;		/* Short name of TRNG */
	char *name;		/* Full Name of TRNG */
	int width;		/* Best width for continuous run test */
	int buffers;		/* Recommended value for rng-buffers */
	double entropy;		/* Recommended value for rng-entropy */
};
static struct trng_params trng_parameters[] = {
	/* Device: Intel FWH TRNG (82802AB/82802AC)
	 * Kernel driver: hw_random or i810_rng
	 * Device width: 8 bits
	 * Entropy: H > 0.999
	 * 
	 * Slow, about 20Kibits/s (variable bitrate) with current
	 * kernel drivers, but the hardware should be capable of
	 * about 75kbit/s.  The kernel driver uses a lot of CPU
	 * time.  It is often misdetected (false positive).
	 *
	 * Whitepaper: Cryptographic Research
	 * http://www.cryptography.com/resources/whitepapers/IntelRNG.pdf
	 */
	{ .name 	= "Intel FWH (82802AB/AC) TRNG",
	  .tag		= "intel",
	  .width	= 32,
	  .buffers	= 5,
	  .entropy	= 0.998 
	},

	/* Device: VIA Padlock (Nehemiah CPU core) TRNG
	 * Kernel driver: hw_random
	 * Device width: 8 bits (internal), 64 bits (external)
	 * Entropy: H > 0.75 (whitener disabled)
	 *          H > 0.99 (whitener enabled)
	 *
	 * Very fast, about 30-50 Mibits/s with the whitener disabled,
	 * and 4-9 Mibits/s with whitener enabled.  The kernel drivers
	 * need patching to archieve better performance (patches and
	 * data from http://peertech.org/hardware/viarng/).
	 *
	 * The hardware has 4 64bit FIFOs to store TRNG data.
	 * 
	 * Whitepaper: Cryptographic Research
	 * http://www.cryptography.com/resources/whitepapers/VIA_rng.pdf
	 */
	{ .name		= "VIA Padlock (Nehemiah) TRNG",
	  .tag		= "via",
	  .width	= 64,
	  .buffers	= 3,
	  .entropy	= 0.75 
	},
	{ NULL },
};

/*
 * command line processing
 */
#define SEEN_OPT_RNGBUFFERS	0x01
#define SEEN_OPT_RNGENTROPY	0x02

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	static unsigned int seen_opt = 0;
	
	switch(key) {
	case 'o':
		arguments->random_name = arg;
		break;
	case 'r':
		arguments->rng_name = arg;
		break;
	case 'p':
		arguments->pidfile_name = arg;
		break;
	case 't': {
		float f;
		if (sscanf(arg, "%f", &f) == 0)
			argp_usage(state);
		else
			arguments->poll_timeout = f;
		break;
	}

	case 'f':
		arguments->daemon = 0;
		break;
	case 'b':
		arguments->daemon = 1;
		break;
	case 's': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 8) || 
			(n > FIPS_RNG_BUFFER_SIZE) || (n & 1))
			argp_usage(state);
		else
			arguments->random_step = n;
		break;
	}
	case 'W': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 0) || (n > 4096))
			argp_usage(state);
		else
			arguments->fill_watermark = n;
		break;
	}

	case 'H': {
		float H;
		if ((sscanf(arg, "%f", &H) == 0) || (H <= 0) || (H > 1))
			argp_usage(state);
		else
			arguments->rng_entropy = H;
			seen_opt |= SEEN_OPT_RNGENTROPY;
		break;
	}

	case 'B': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 1) || (n > MAX_RNG_BUFFERS ))
			argp_usage(state);
		else
			arguments->rng_buffers = n;
			seen_opt |= SEEN_OPT_RNGBUFFERS;
		break;
	}

	case ARGP_RNGD_CMDLINE_TRNG: {	/* --trng */
		int i = 0;
		if (strcasecmp(arg, "help") == 0) {
			fprintf(state->out_stream,
				"TRNG      Description\n");
			while (trng_parameters[i].tag) {
				fprintf(state->out_stream, "%-8s  \"%s\"\n",
					trng_parameters[i].tag,
					trng_parameters[i].name);
				fprintf(state->out_stream,
					"%-10s"
					"rng-entropy=%0.3f, "
					"rng-buffers=%d;\n",
					" ", trng_parameters[i].entropy,
					trng_parameters[i].buffers);
				i++;
			}
			exit(EXIT_SUCCESS);
		}
		while (trng_parameters[i].tag) {
			if (strcasecmp(arg, trng_parameters[i].tag) == 0) {
				if (! (seen_opt & SEEN_OPT_RNGENTROPY))
					arguments->rng_entropy =
						trng_parameters[i].entropy;
				if (! (seen_opt & SEEN_OPT_RNGBUFFERS))
					arguments->rng_buffers =
						trng_parameters[i].buffers;
				break;
			}
			i++;
		}
		if (!trng_parameters[i].tag)
			argp_failure(state, argp_err_exit_status, 0,
				"Unknown TRNG, try --trng=help");
		break;
	}

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
static struct argp argp = { options, parse_opt, NULL, doc };

/*
 * Daemon needs
 */
void die(int status)
{
	if (am_daemon) syslog(LOG_ERR, "Exiting with status %d...", status);
	exit(status);
}

/* 
 * Write our pid to our pidfile, and lock it
 */
static void get_lock(const char* pidfile_name)
{
    int otherpid = 0;

    if (!daemon_lockfp) {
	    if (((daemon_lockfd = open(pidfile_name, O_RDWR|O_CREAT, 0644)) == -1)
		|| ((daemon_lockfp = fdopen(daemon_lockfd, "r+"))) == NULL) {
		    message(LOG_ERR, "can't open or create %s", pidfile_name);
		   die(EXIT_USAGE);
    	    }
    }

#ifdef HAVE_FLOCK
    if ( flock(daemon_lockfd, LOCK_EX|LOCK_NB) != 0 ) {
#else
    if ( lockf(fileno(daemon_lockfp), F_TLOCK, 0) != 0 ) {
#endif
    		rewind(daemon_lockfp);
		fscanf(daemon_lockfp, "%d", &otherpid);
		message(LOG_ERR, "can't lock %s, running daemon's pid may be %d",
		      pidfile_name, otherpid);
		die(EXIT_USAGE);
	    }

    fcntl(daemon_lockfd, F_SETFD, 1);

    rewind(daemon_lockfp);
    fprintf(daemon_lockfp, "%d\n", (int) getpid());
    fflush(daemon_lockfp);
    ftruncate(fileno(daemon_lockfp), ftell(daemon_lockfp));
}

/*
 * Signal handling
 */
static void sigterm_handler(int sig)
{
	gotsigterm = 128 | sig;
}

static void sigusr1_handler(int sig)
{
	gotsigusr1 = 1;
}

static void init_sighandlers(void)
{
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	action.sa_handler = sigterm_handler;

	/* Handle SIGTERM and SIGINT the same way */
	if (sigaction(SIGTERM, &action, NULL) < 0) {
		message(LOG_ERR,
			"unable to install signal handler for SIGTERM: %s",
			strerror(errno));
		die(EXIT_OSERR);
	}
	if (sigaction(SIGINT, &action, NULL) < 0) {
	        message(LOG_ERR,
			"unable to install signal handler for SIGINT: %s",
			strerror(errno));
	        die(EXIT_OSERR);
	}

	/* Handle SIGUSR1 in a more friendly way */
	action.sa_flags = SA_RESTART;
	action.sa_handler = sigusr1_handler;
	if (sigaction(SIGUSR1, &action, NULL) < 0) {
	        message(LOG_ERR,
			"unable to install signal handler for SIGUSR1: %s",
			strerror(errno));
	        die(EXIT_OSERR);
	}
}

/*
 * Statistics
 */
static void init_rng_stats(void)
{
	set_stat_prefix("stats: ");

	memset(&rng_stats, 0, sizeof(rng_stats));
	rng_stats.buffer_lowmark = rng_buffers - 1; /* one is always in use */

	pthread_mutex_init(&rng_stats.group1_mutex, NULL);
	pthread_mutex_init(&rng_stats.group2_mutex, NULL);
	pthread_mutex_init(&rng_stats.group3_mutex, NULL);
}

static void dump_rng_stats(void)
{
	int j;
	char buf[256];

	pthread_mutex_lock(&rng_stats.group1_mutex);
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"bits received from TRNG source",
			rng_stats.bytes_received * 8));
	pthread_mutex_unlock(&rng_stats.group1_mutex);
	pthread_mutex_lock(&rng_stats.group3_mutex);
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"bits sent to kernel pool",
			rng_stats.bytes_sent * 8));
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"entropy added to kernel pool",
			rng_stats.entropy_sent));
	pthread_mutex_unlock(&rng_stats.group3_mutex);
	pthread_mutex_lock(&rng_stats.group2_mutex);
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"FIPS 140-2 successes",
			rng_stats.good_fips_blocks));
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"FIPS 140-2 failures",
			rng_stats.bad_fips_blocks));
	for (j = 0; j < N_FIPS_TESTS; j++)
		message(LOG_INFO, dump_stat_counter(buf, sizeof(buf), fips_test_names[j],
				rng_stats.fips_failures[j]));
	pthread_mutex_unlock(&rng_stats.group2_mutex);
	pthread_mutex_lock(&rng_stats.group1_mutex);
	message(LOG_INFO, dump_stat_bw(buf, sizeof(buf),
			"TRNG source speed", "bits",
			&rng_stats.source_blockfill, FIPS_RNG_BUFFER_SIZE*8));
	pthread_mutex_unlock(&rng_stats.group1_mutex);
	pthread_mutex_lock(&rng_stats.group2_mutex);
	message(LOG_INFO, dump_stat_bw(buf, sizeof(buf),
			"FIPS tests speed", "bits",
			&rng_stats.fips_blockfill, FIPS_RNG_BUFFER_SIZE*8));
	pthread_mutex_unlock(&rng_stats.group2_mutex);
	pthread_mutex_lock(&rng_stats.group3_mutex);
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"Lowest ready-buffers level",
			rng_stats.buffer_lowmark));
	message(LOG_INFO, dump_stat_counter(buf, sizeof(buf),
			"Entropy starvations",
			rng_stats.sink_starved));
	message(LOG_INFO, dump_stat_stat(buf, sizeof(buf),
			"Time spent starving for entropy",
			"us",
			&rng_stats.sink_wait));
	pthread_mutex_unlock(&rng_stats.group3_mutex);
}

int main(int argc, char **argv)
{
	int fd;
	pthread_t t1,t2,t3;
	int sleeptime;

	argp_parse(&argp, argc, argv, 0, 0, arguments);

	/* close useless FDs we might have gotten somehow */
	for(fd = 3; fd < 250; fd++) (void) close(fd);

	/* Init entropy source, and open TRNG device */
	init_entropy_source(arguments->rng_name);

	/* Init entropy sink and open random device */
	init_kernel_rng(arguments->random_name);

	if (arguments->daemon) {
		/* check if another rngd is running, 
		 * create pidfile and lock it */
		get_lock(arguments->pidfile_name);

		if (daemon(0, 0) < 0) {
			message(LOG_ERR, "can't daemonize: %s",
					strerror(errno));
			return EXIT_OSERR;
		}

		openlog(PROGNAME, 0, SYSLOG_FACILITY);
		am_daemon = 1;

		/* update pidfile */
		get_lock(arguments->pidfile_name);
	}

	masterprocess = getpid();
	message(LOG_INFO, PROGNAME " " VERSION " starting up...");

	/* Init data structures */
	init_rng_buffers(arguments->rng_buffers);
	init_rng_stats();
	init_sighandlers();

	/* Fire up worker threads */
	if (pthread_create(&t1, NULL, &do_rng_data_source_loop, NULL) |
	    pthread_create(&t2, NULL, &do_rng_fips_test_loop, NULL ) |
	    pthread_create(&t3, NULL, &do_rng_data_sink_loop, NULL )) {
		message(LOG_ERR, "Insufficient resources to start threads");
		die(EXIT_OSERR);
	}

	/* 
	 * All we can do now is spin around waiting for a hit to the head.
	 * Dump stats every hour, and at exit...
	 */
	sleeptime = 3600;
	while (!gotsigterm) {
		sleeptime = sleep(sleeptime);
		if ((sleeptime == 0) || gotsigusr1 || gotsigterm) {
			dump_rng_stats();
			sleeptime = 3600;
			gotsigusr1 = 0;
		}
	}

	if (exitstatus == EXIT_SUCCESS)
		message(LOG_INFO, "Exiting...");
	else
		message(LOG_ERR, 
			"Exiting with status %d", exitstatus);

	exit(exitstatus);
}
