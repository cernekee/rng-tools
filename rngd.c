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
 * Copyright (C) 2001-2004 Jeff Garzik
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
#include <stdarg.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>
#include <syslog.h>
#include <pthread.h>

#include <sys/file.h>
#include <assert.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "stats.h"
#include "util.h"
#include "rngd_threads.h"
#include "rngd_signals.h"
#include "rngd_entsource.h"
#include "rngd_linux.h"

#define XSTR(x) STR(x)
#define STR(x) #x
#define PROGNAME "rngd"

/*
 * Globals
 */

#define	RNGD_STAT_SLEEP_TIME 3600

/* Statistics */
struct rng_stats rng_stats;

/* Background/daemon mode */
pid_t masterprocess;			/* PID of the master process */
int am_daemon;				/* Nonzero if we went daemon */
int exitstatus = EXIT_SUCCESS;		/* Exit status on SIGTERM */
static FILE *daemon_lockfp = NULL;	/* Lockfile file pointer */
static int daemon_lockfd;		/* Lockfile file descriptor */

kernel_mode_t kernel;			/* Kernel compatibility mode */

/* Command line arguments and processing */
const char *argp_program_version = 
	PROGNAME " " VERSION "\n"
	"Copyright (c) 2001-2004 by Jeff Garzik\n"
	"Copyright (c) 2004,2005 by Henrique de Moraes Holschuh\n"
	"Copyright (c) 2001 by Philipp Rumpf\n"
#ifdef VIA_ENTSOURCE_DRIVER
	"VIA PadLock RNG code based on work by Martin Peck\n"
#endif
	"This is free software; see the source for copying conditions.  "
	"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR "
	"A PARTICULAR PURPOSE.";
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
error_t argp_err_exit_status = EXIT_USAGE;

static char doc[] =
	"Check and feed random data from hardware device to kernel entropy pool.\n";

#define ARGP_RNGD_CMDLINE_HRNG		0x81
#define ARGP_RNGD_CMDLINE_TIMEOUT	0x82
	
static struct argp_option options[] = {
    	/**/ { 0, 0, 0, 0, "Program control" }, /* ======================== */
	{ "foreground",	'f', 0, 0, "Do not fork and become a daemon" },

	{ "background", 'b', 0, 0, "Become a daemon (default)" },

	{ "pidfile", 'p', "file", 0,
	  "Path to file to write PID to in daemon mode "
	  "(default: " PIDFILE ")" },

	{ "rng-buffers", 'B', "n", 0,
	  "Number of buffers (default: 3),  0 < n <= " XSTR(MAX_RNG_BUFFERS) },

	/**/ { 0, 0, 0, 0, "Input (entropy source) control" }, /* ========= */

	{ "rng-driver", 'R', "name", 0,
	  "Select the entropy source driver: \"stream\" or \"viapadlock\" "
	  "(default: stream). "
	  "\"stream\" is a general purpose Unix stream input driver, and "
	  "honours rng-device, rng-timeout, and rng-entropy; "
	  "\"viapadlock\" is a driver for the VIA PadLock TRNG. It honours "
	  "rng-entropy and rng-timeout" },

	{ "rng-device", 'r', "file", 0,
	  "Entropy source (default: " DEVHWRANDOM ")" },

	{ "rng-timeout", 'T', "n", 0,
	  "Wait at most \"n\" seconds for the entropy source to provide "
	  "some initial data. Set to zero to wait forever (default: 10s)" },

	{ "rng-entropy", 'H', "n", 0,
	  "Entropy per bit of data received from entropy source (default: "
	  "1.0 for the \"stream\" entropy source driver, automatic for other "
	  "entropy source drivers), 0 < n <= 1.0" },

	{ "rng-quality", 'Q', "quality", 0,
	  "If the entropy source supports it, selects the quality of the "
	  "random data it will generate. Quality is: \"default\", \"low\", "
	  "\"medium\" or \"high\". Do not use anything but \"high\" if the "
	  "entropy sink will use the random data directly, instead of using "
	  "it to seed a PRNG/entropy pool. Ignored by the \"stream\" "
	  "entropy source driver" },

	{ "hrng", ARGP_RNGD_CMDLINE_HRNG, "name", 0,
	  "Selects known-good defaults for rng-driver, rng-timeout and "
	  "rng-entropy, for a given TRNG. These can be overriden by specifying "
	  "one of those options explicitly. Use --hrng=help to get a list of "
	  "known TRNGs" },

	/**/ { 0, 0, 0, 0, "Output (entropy sink) control" }, /* ========== */

	/* { "output-driver", 'O', "name", 0,
	  "Entropy sink driver: (default: linux-random). "
	  "\"linux-random\" is the usual Linux /dev/random kernel driver.  It "
	  "honours random-device, random-step, feed-interval, fill-watermark."
	   }, */

	{ "random-device", 'o', "file", 0,
	  "Kernel device used for entropy output (default: " DEVRANDOM ")" },

	{ "random-step", 's', "n", 0,
	  "Number of bytes written to random-device at a time (default: 64), "
	  "8 <= n <= " XSTR(FIPS_RNG_BUFFER_SIZE) ", \"n\" must be even" },

	{ "timeout", ARGP_RNGD_CMDLINE_TIMEOUT, "n", 0,
	  "Deprecated, same as --feed-interval" },

	{ "feed-interval", 't', "n", 0,
	  "When the entropy pool is full, write to random-device every "
	  "\"n\" seconds. Set to zero to disable (default: 60)" },

	{ "fill-watermark", 'W', "n[%]", 0,
	  "Do not stop feeding entropy to random-device until at least "
	  "\"n\" bits of entropy are available in the pool. \"n\" can be "
	  "the absolute number of bits, or a percentage of the pool size "
	  "(default: 50%), "
	  "0 <= n <= kernel random pool size, or 0% <= n <= 100%" },

	{ 0 },
};
static struct arguments default_arguments = {
	.rng_name	= DEVHWRANDOM,
	.random_name	= DEVRANDOM,
	.pidfile_name	= PIDFILE,
	.feed_interval	= 60,
	.random_step	= 64,
	.fill_watermark = -50,
	.rng_timeout	= 10,
	.daemon		= 1,
	.rng_entropy	= 1.0,
	.rng_buffers	= 3,
	.rng_quality	= 0,
	.rng_driver	= RNGD_ENTSOURCE_UNIXSTREAM,
};
struct arguments *arguments = &default_arguments;

/* Predefined known-good values for HRNGs */
struct trng_params {
	char *tag;		/* Short name of HRNG */
	char *name;		/* Full Name of HRNG */
	int width;		/* Best width for continuous run test */
	int buffers;		/* Recommended value for rng-buffers */
	double entropy;		/* Recommended value for rng-entropy */
	entropy_source_driver_t driver;  /* Entropy source driver */
};
static struct trng_params trng_parameters[] = {
	/* Device: Intel FWH RNG (82802AB/82802AC)
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
	{ .name 	= "Intel FWH (82802AB/AC) RNG",
	  .tag		= "intelfwh",
	  .width	= 32,
	  .buffers	= 5,
	  .entropy	= 0.998,
	  .driver	= RNGD_ENTSOURCE_UNIXSTREAM,
	},

	/* Device: VIA Padlock (Nehemiah CPU core) RNG
	 * Kernel driver: hw_random
	 * User space driver: RNGD_ENTSOURCE_VIA
	 * Device width: 8 bits (internal), 64 bits (external)
	 * Entropy: H > 0.75 (whitener disabled)
	 *          H > 0.99 (whitener enabled)
	 *
	 * Very fast, about 30-50 Mibits/s with the whitener disabled,
	 * and 4-9 Mibits/s with whitener enabled.  The kernel drivers
	 * need patching to archieve better performance (patches and
	 * data from http://peertech.org/hardware/viarng/).
	 *
	 * The hardware has 4 64bit FIFOs to store RNG data.
	 * 
	 * Whitepaper: Cryptographic Research
	 * http://www.cryptography.com/resources/whitepapers/VIA_rng.pdf
	 */
	{ .name		= "VIA Padlock RNG (Kernel driver, deprecated)",
	  .tag		= "viakernel",
	  .width	= 64,
	  .buffers	= 3,
	  .entropy	= 0.75,
	  .driver	= RNGD_ENTSOURCE_UNIXSTREAM,
	},
	{ .name		= "VIA Padlock RNG",
	  .tag		= "viapadlock",
	  .width	= 64,
	  .buffers	= 3,
	  .entropy	= 0.0,
	  .driver	= RNGD_ENTSOURCE_VIAPADLOCK,
	},
	{ NULL },
};

/*
 * command line processing
 */
#define SEEN_OPT_RNGBUFFERS	0x01
#define SEEN_OPT_RNGENTROPY	0x02
#define SEEN_OPT_RNGDRIVER	0x04

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

	case ARGP_RNGD_CMDLINE_TIMEOUT: 	/* --timeout */
		message (LOG_WARNING, "Warning: --timeout is deprecated, "
			 "use --feed-interval instead");
		/* fallthrough */
	case 't': {
		long int n;
		char *p;
		n = strtol(arg, &p, 10);
		if ((p == arg) || (*p != 0) || (n < 0) || (n >= INT_MAX))
			argp_usage(state);
		else
			arguments->feed_interval = n;
		break;
	}

	case 'T': {
		long int n;
		char *p;
		n = strtol(arg, &p, 10);
		if ((p == arg) || (*p != 0) || (n < 0) || (n >= INT_MAX))
			argp_usage(state);
		else
			arguments->rng_timeout = n;
		break;
	}

	case 'f':
		arguments->daemon = 0;
		break;
	case 'b':
		arguments->daemon = 1;
		break;
	case 's': {
		long int n;
		char *p;
		n = strtol(arg, &p, 10);
		if ((p == arg) || (*p != 0) || (n < 8) ||
		    (n > FIPS_RNG_BUFFER_SIZE) || (n & 1))
			argp_usage(state);
		else
			arguments->random_step = n;
		break;
	}
	case 'W': {
		long int n;
		char *p;
		n = strtol(arg, &p, 10);
		if ((p != arg) && (*p == '%')) {
			p++;
			if ((*p != 0) || (n < 0) || (n > 100))
				argp_usage(state);
			else
				arguments->fill_watermark = -n;
		} else {
			if ((p == arg) || (*p != 0) || (n >= 131072))
				argp_usage(state);
			else
				arguments->fill_watermark = n;
		}
		break;
	}

	case 'H': {
		float H;
		char *p;
		H = strtof(arg, &p);
		if ((p == arg) || (*p != 0) || (H <= 0) || (H > 1))
			argp_usage(state);
		else {
			arguments->rng_entropy = H;
			seen_opt |= SEEN_OPT_RNGENTROPY;
		}
		break;
	}

	case 'B': {
		long int n;
		char *p;
		n = strtol(arg, &p, 10);
		if ((p == arg) || (*p != 0) || 
		    (n < 1) || (n > MAX_RNG_BUFFERS ))
			argp_usage(state);
		else {
			arguments->rng_buffers = n;
			seen_opt |= SEEN_OPT_RNGBUFFERS;
		}
		break;
	}

	case 'R': {
		if (seen_opt & SEEN_OPT_RNGDRIVER) {
			argp_usage(state);
		} else if (strcasecmp(arg, "stream") == 0) {
			arguments->rng_driver = RNGD_ENTSOURCE_UNIXSTREAM;
			seen_opt |= SEEN_OPT_RNGDRIVER;
		} else if (strcasecmp(arg, "viapadlock") == 0) { 
			arguments->rng_driver = RNGD_ENTSOURCE_VIAPADLOCK;
			if (! (seen_opt & SEEN_OPT_RNGENTROPY))
				arguments->rng_entropy = 0.0;
			seen_opt |= SEEN_OPT_RNGDRIVER;
		} else {
			argp_usage(state);
		}
		break;
	}

	case 'Q': {
		static const char* const quality_names[4] = {
			"default", "low", "medium", "high"
		};

		int i;
		for(i = 0; i < 4; i++) {
			if (strcasecmp(arg, quality_names[i]) == 0) {
				arguments->rng_quality = i;
				break;
			}
		}
		if (i >= 4) argp_usage(state);
		break;
	}

	case ARGP_RNGD_CMDLINE_HRNG: {	/* --hrng */
		int i = 0;
		if (strcasecmp(arg, "help") == 0) {
			fprintf(state->out_stream,
				"RNG         Description\n");
			while (trng_parameters[i].tag) {
				fprintf(state->out_stream, "%-10s  \"%s\"\n",
					trng_parameters[i].tag,
					trng_parameters[i].name);
				if (trng_parameters[i].entropy != 0.0) {
					fprintf(state->out_stream,
						"%-12s"
						"rng-driver=%s, "
						"rng-entropy=%0.3f, "
						"rng-buffers=%d;\n",
						" ", 
						entropy_source_driver_name(trng_parameters[i].driver),
						trng_parameters[i].entropy,
						trng_parameters[i].buffers);
				} else {
					fprintf(state->out_stream,
						"%-12s"
						"rng-driver=%s, "
						"rng-entropy=auto, "
						"rng-buffers=%d;\n",
						" ", 
						entropy_source_driver_name(trng_parameters[i].driver),
						trng_parameters[i].buffers);
				}
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
				if (! (seen_opt & SEEN_OPT_RNGDRIVER))
					arguments->rng_driver =
						trng_parameters[i].driver;
				break;
			}
			i++;
		}
		if (!trng_parameters[i].tag)
			argp_failure(state, argp_err_exit_status, 0,
				"Unknown RNG, try --hrng=help");
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

void message(int priority, const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (am_daemon) {
		vsyslog(priority, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

void message_strerr(int priority, int errornumber,
                     const char* fmt, ...)
{
	va_list ap;
	char errbuf[STR_BUF_LEN];
	char *strerrbuf = errbuf;
	char *errfmt = NULL;
	int s;

	va_start(ap, fmt);

	memset(errbuf, 0, sizeof(errbuf));
	if (errornumber) 
		strerrbuf = strerror_r(errornumber, errbuf, sizeof(errbuf)-1);
	s = strlen(fmt) + strlen(strerrbuf) + 3;
	errfmt = malloc(s);
	if (errfmt) {
		snprintf(errfmt, s, "%s: %s", fmt, strerrbuf);
		errfmt[s-1] = 0;
	} else {
		errfmt = (char *)fmt;
	}
	
	if (am_daemon) {
		vsyslog(priority, errfmt, ap);
	} else {
		vfprintf(stderr, errfmt, ap);
		fprintf(stderr, "\n");
	}

	if (errfmt != fmt) free(errfmt);

	va_end(ap);
}


/* 
 * Write our pid to our pidfile, and lock it
 */
static void get_lock(const char* pidfile_name)
{
	int otherpid = 0;
	int r;

	assert(pidfile_name != NULL);

	if (!daemon_lockfp) {
		if (((daemon_lockfd = open(pidfile_name, O_RDWR|O_CREAT, 0644)) == -1)
		|| ((daemon_lockfp = fdopen(daemon_lockfd, "r+"))) == NULL) {
			message_strerr(LOG_ERR, errno, "can't open or create %s", 
			pidfile_name);
		   die(EXIT_USAGE);
		}
		fcntl(daemon_lockfd, F_SETFD, 1);

		do {
			r = flock(daemon_lockfd, LOCK_EX|LOCK_NB);
		} while (r && (errno == EINTR));

		if (r) {
			if (errno == EWOULDBLOCK) {
				rewind(daemon_lockfp);
				fscanf(daemon_lockfp, "%d", &otherpid);
				message(LOG_ERR,
					"can't lock %s, running daemon's pid may be %d",
					pidfile_name, otherpid);
			} else {
				message_strerr(LOG_ERR, errno,
					"can't lock %s", pidfile_name);
			}
			die(EXIT_USAGE);
		}
	}

	rewind(daemon_lockfp);
	fprintf(daemon_lockfp, "%ld\n", (long int) getpid());
	fflush(daemon_lockfp);
	ftruncate(fileno(daemon_lockfp), ftell(daemon_lockfp));
}


/*
 * Statistics, n is the number of rng buffers
 */
static void init_rng_stats(int n)
{
	set_stat_prefix("stats: ");

	memset(&rng_stats, 0, sizeof(rng_stats));
	rng_stats.buffer_lowmark = n - 1; /* one is always in use */

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
			"bits received from HRNG source",
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
			"HRNG source speed", "bits",
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

	kernel = kernel_mode();
	argp_parse(&argp, argc, argv, 0, 0, arguments);

	/* Make sure kernel is supported */
	if (kernel == KERNEL_UNSUPPORTED) {
		message(LOG_ERR, "Unsupported kernel detected, exiting...");
		die (EXIT_OSERR);
	}

	/* close useless FDs we might have gotten somehow */
	for(fd = 3; fd < 250; fd++) (void) close(fd);

	/* Init statistics */
	init_rng_stats(arguments->rng_buffers);

	/* Init signal handling early */
	init_sighandlers();

	/* Init entropy source */
	init_entropy_source();

	/* Init entropy sink */
	init_kernel_rng();

	if (arguments->daemon) {
		/* check if another rngd is running, 
		 * create pidfile and lock it */
		get_lock(arguments->pidfile_name);

		if (daemon(0, 0) < 0) {
			message_strerr(LOG_ERR, errno, "can't daemonize");
			return EXIT_OSERR;
		}

		openlog(PROGNAME, LOG_PID, SYSLOG_FACILITY);
		am_daemon = 1;

		/* update pidfile */
		get_lock(arguments->pidfile_name);
	}

	masterprocess = getpid();
	message(LOG_INFO, PROGNAME " " VERSION " starting up...");

	/* post-fork initialization */
	init_rng_buffers(arguments->rng_buffers);
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
	sleeptime = RNGD_STAT_SLEEP_TIME;
	while (!gotsigterm) {
		sleeptime = sleep(sleeptime);
		if ((sleeptime == 0) || gotsigusr1 || gotsigterm) {
			dump_rng_stats();
			sleeptime = RNGD_STAT_SLEEP_TIME;
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
