#include "patch.h"
#include "log.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(HAVE_OATH)
#   include <liboath/oath.h>
#endif // HAVE_OATH

#if defined(HAVE_OATH)

static int _patch_totp_generate(const char *base32_secret, char *output_otp)
{
	int rc;
	char *secret;
	size_t secretlen = 0;
	time_t now;

	rc = oath_base32_decode(base32_secret, strlen(base32_secret),
	                        &secret, &secretlen);
	if (rc != OATH_OK) {
		log_error("base32 decoding failed: %s\n", oath_strerror(rc));
		return rc;
	}

	now = time(NULL);
	rc = oath_totp_generate2(secret,
	                         secretlen,
	                         now,
	                         OATH_TOTP_DEFAULT_TIME_STEP_SIZE,
	                         0,
	                         6,
	                         0,
	                         output_otp);
	if (rc != OATH_OK)
		log_error("generating one-time password failed: %s\n", oath_strerror(rc));
	else
		log_debug("OTP: %s\n", output_otp);
	free(secret);
	return rc;
}

int patch_totp_generate(const char *base32_secret, char *output_otp)
{
	int rc;

	rc = oath_init();
	if (rc != OATH_OK) {
		log_error("liboath initialization failed: %s\n", oath_strerror(rc));
		return rc;
	}

	rc = _patch_totp_generate(base32_secret, output_otp);
	oath_done();
	return rc;
}

#else

int patch_totp_generate(const char *base32_secret, char *output_otp)
{
	log_error("Current version compiled without liboath, Don't set --otp-secret.\n");
	return -1;
}

#endif // HAVE_OATH
