/*
 * rngd_linux.h -- Entropy sink for the Linux Kernel (/dev/random)
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

#ifndef RNGD_LINUX__H
#define RNGD_LINUX__H

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>

/*
 * Initialize the interface to the Linux Kernel
 * entropy pool (through /dev/random)
 */
extern void init_kernel_rng( void );

/*
 * RNG data sink thread
 *
 * This thread feeds the output device with data that has been approved by the
 * FIPS tests.
 *
 * Only one data sink thread is supported.
 */
extern void *do_rng_data_sink_loop( void *trash );

#endif /* RNGD_LINUX__H */

