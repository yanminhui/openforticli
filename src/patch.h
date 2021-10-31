/*
 *  Copyright (C) 2021 Bryan Yan
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OPENFORTICLI_PATCH_H
#define OPENFORTICLI_PATCH_H

#include <stddef.h>

/*
 * patch_totp_generate:
 * @base32_secret: the shared secret string
 * @output_otp: output buffer, must have room for the output OTP plus zero
 *
 * Generate a one-time-password using the time-variant TOTP algorithm
 * described in RFC 6238.
 *
 * Requirements: liboath
 *
 * Returns: On success, zero is returned, otherwise an error code is returned.
 */
extern int patch_totp_generate(const char *base32_secret, char *output_otp);

/*
 * return interval ms if true else -1.
 */
extern double ping_host_ip(const char *domain);

/*
 * preferred_host:
 * @hosts: the host list join by `;`
 * @output_host: output buffer, must have room for the output host plus zero
 * @num: maximum number of characters to be copied from source
 */
extern void preferred_host(char *hosts, char *output_host, size_t num);

#endif
