/* rc4-based pseudo-random number generator for hping
 * Copyright (C) 2003 Salvatore Sanfilippo
 * This software is released under the GPL license
 * All rights reserved */

/* $Id: random.c,v 1.4 2025/07/17 11:10:00 user Exp $ */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include "fixtypes.h"

u_int32_t hp_rand(void);

/* The rc4 sbox */
static unsigned char rc4_sbox[256];
/* This flag is used to initialize the sbox the first time,
 * without an explicit initialization step outside this file */
static int rc4_seedflag = 0;

/* read exactly count bytes or return -1 on failure */
static int safe_read(int fd, void* buf, size_t count) {
    unsigned char* p = buf;

    while (count) {
        ssize_t n = read(fd, p, count);
        if (n < 0) {
            if (errno == EINTR)
                continue; /* interrupted by signal, retry */
            return -1;    /* real error */
        }
        if (n == 0)
            return -1; /* unexpected EOF */
        p += n;
        count -= n;
    }
    return 0;
}

/* Initialize the sbox with pseudo‑random data */
static void hp_rand_init(void) {
    int i, fd;

    /* strong sbox initialization */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        if (safe_read(fd, rc4_sbox, sizeof(rc4_sbox)) == -1) {
            /* fall through to weaker seeding if /dev/urandom failed */
        }
        close(fd);
    }

    /* weaker sbox initialization */
    for (i = 0; i < 256; i++) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        if (i & 1)
            rc4_sbox[i] ^= (tv.tv_usec >> (i & 0xF)) & 0xFF;
        else
            rc4_sbox[i] ^= (tv.tv_sec >> (i & 0xF)) & 0xFF;
    }
    rc4_seedflag = 1;
}

/* Generates a 32‑bit random number using an RC4‑like algorithm */
u_int32_t hp_rand(void) {
    u_int32_t r = 0;
    unsigned char* rc = (unsigned char*)&r;
    static unsigned int i = 0, j = 0;
    unsigned int si, sj, x;

    /* initialization, only needed the first time */
    if (!rc4_seedflag)
        hp_rand_init();

    /* generate 4 bytes of pseudo‑random data using RC4 */
    for (x = 0; x < 4; x++) {
        i = (i + 1) & 0xff;
        si = rc4_sbox[i];
        j = (j + si) & 0xff;
        sj = rc4_sbox[j];
        rc4_sbox[i] = sj;
        rc4_sbox[j] = si;
        *rc++ = rc4_sbox[(si + sj) & 0xff];
    }
    return r;
}
