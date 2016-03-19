/*
 * Copyright (c) 2016 Kurt Roeckx <kurt@roeckx.be>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include "checks.h"

static const char *error_strings[] =
{
	"E: Error parsing certificate\n", /* ERR_INVALID*/
	"E: Issuer without organization name\n", /* ERR_ISSUER_ORG_NAME*/
	"E: Issuer without country name\n", /* ERR_ISSUER_COUNTRY */
	"E: Subject without OrganizationName but with StreetAddress\n", /* ERR_SUBJECT_ADDR */
	"E: Subject with OrganizationName but without StateOrProvince or LocalityName\n", /* ERR_SUBJECT_ORG_NO_PLACE */
	"E: Subject without OrganizationName but with StateOrProvince or LocalityName\n", /* ERR_SUBJECT_NO_ORG_PLACE */
	"E: Fails decoding the characterset\n", /*ERR_INVALID_ENCODING */
	"E: Contains a null character in the distinguished name\n", /* ERR_STRING_WITH_NUL */
	"E: Name entry contains an invalid type\n", /* ERR_INVALID_NAME_ENTRY_TYPE */
	"E: The distinguished name contains non-printable control characters\n", /* ERR_NON_PRINTABLE */
	"E: Subject with OrganizationName but without country name\n", /* ERR_SUBJECT_COUNTRY */
	"E: Domain validated certificate but with organization name or address\n", /* ERR_DOMAIN_WITH_ORG_OR_ADDRESS */
	"E: Identity validated certificate but without organization name or address\n", /* ERR_IDENTITY_WITHOUT_ORG_OR_ADDRESS */
	"E: No policy extension\n", /* ERR_NO_POLICY */
	"E: No Subject alternative name extension\n", /* ERR_NO_SUBJECT_ALT_NAME */
	"E: Certificate not version 3\n", /* ERR_NOT_VERSION3 */
	"E: Error parsing URL\n", /* ERR_INVALID_URL */
	"E: The certificate is valid for longer than 60 months\n", /* ERR_LONGER_60_MONTHS */
	"E: countryName not 2 characters long\n", /* ERR_COUNTRY_SIZE */
	"E: Invalid time format\n", /* ERR_INVALID_TIME_FORMAT */
	"E: Duplicate extention\n", /* ERR_DUPLICATE_EXTENTION */
	"E: Invalid CRL distribution point\n", /* ERR_INVALID_CRL_DIST_POINT */
	"E: Invalid display text type\n", /* ERR_INVALID_DISPLAY_TEXT_TYPE */
	"E: Invalid display text length\n", /* ERR_INVALID_DISPLAY_TEXT_LENGTH */
	"E: Invalid user notice type\n", /* ERR_INVALID_TYPE_USER_NOTICE */
	"E: Invalid policy qualifier id\n", /* ERR_INVALID_POLICY_QUALIFIER_ID */
	"E: Individual without name\n", /* ERR_INDIVDUAL_WITHOUT_NAME */
	"E: Individual without country\n", /* ERR_INDIVDUAL_WITHOUT_COUNTRY */
	"E: EV certificate without organization\n", /* ERR_EV_WITHOUT_ORGANIZATION */
	"E: EV certificate without business\n", /* ERR_EV_WITHOUT_BUSINESS */
	"E: EV certificate without jurisdiction country\n", /* ERR_EV_WITHOUT_JURISDICTION_COUNTRY */
	"E: EV certificate without number\n", /* ERR_EV_WITHOUT_NUMBER */
	"E: EV certificate without locality\n", /* ERR_EV_WITHOUT_LOCALITY */
	"E: EV certificate without country\n" /* ERR_EV_WITHOUT_COUNTRY */
};

static const char *warning_strings[] = {
	"W: The distinguished name contains something that is not a PrintableString or UTF8String\n", /* WARN_NON_PRINTABLE_STRING */
	"W: The distinguished name makes use of an IA5String\n", /* WARN_IA5 */
	"W: The certificate is valid for longer than 39 months\n", /* WARN_LONGER_39_MONTHS */
	"W: CA certificate checked as if it was a subscriber certificate\n", /* WARN_CHECKED_AS_SUBSCRIBER */
	"W: Subscriber certificate checked as if it was a CA certificate\n", /* WARN_CHECKED_AS_CA */
	"W: CRL distribution point uses relative name\n" /* WARN_CRL_RELATIVE */
};

static const char *info_strings[] = {
	"I: Subject has a deprecated CommonName\n", /* INF_SUBJECT_CN */
	"I: String not checked\n", /* INF_STRING_NOT_CHECKED */
	"I: CRL is not a URL\n", /* INF_CRL_NOT_URL */
	"I: Unknown validation policy\n" /* INF_UNKNOWN_VALIDATION */
};

/* 
 * Turn the error information into strings.
 * Returns a buffer that should be free()d
 */
char *get_messages()
{
	char *buffer;

	/* Should be large enough for all strings. */
	buffer = malloc(8192);
	buffer[0] = '\0';

	for (int i = 0; i <= ERR_EV_WITHOUT_COUNTRY; i++)
	{
		if (GetBit(errors, i))
		{
			strcat(buffer, error_strings[i]);
		}
	}

	for (int i = 0; i <= WARN_CRL_RELATIVE; i++)
	{
		if (i == WARN_IA5)
		{
			continue;
		}
		if (GetBit(warnings, i))
		{
			strcat(buffer, warning_strings[i]);
		}
	}

	for (int i = 0; i <= INF_UNKNOWN_VALIDATION; i++)
	{
		if (GetBit(info, i))
		{
			strcat(buffer, info_strings[i]);
		}
	}

	return buffer;
}

