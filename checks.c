/*
 * Copyright (c) 2014-2016 Kurt Roeckx <kurt@roeckx.be>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <ctype.h>
#include <stdbool.h>

#include <gnutls/x509.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "checks.h"

static iconv_t iconv_utf8;
static iconv_t iconv_ucs2;
static iconv_t iconv_t61;

static const char *OIDStreetAddress = "2.5.4.9";
static const char *OIDCabDomainValidated = "2.23.140.1.2.1";
static const char *OIDCabIdentityValidated = "2.23.140.1.2.2";
static const char *OIDSubjectAltName = "2.5.29.17";

unsigned int errors[1];
unsigned int warnings[1];
unsigned int info[1];

static void SetBit(unsigned int *val, int bit)
{
	val[bit/(sizeof(int)*8)] |= (1 << (bit % (sizeof(int)*8)));
}

int GetBit(unsigned int *val, int bit)
{
	return (val[bit/(sizeof(int)*8)] & (1 << (bit % (sizeof(int)*8)))) != 0;
}

#define SetError(bit) SetBit(errors, bit)
#define SetWarning(bit) SetBit(warnings, bit)
#define SetInfo(bit) SetBit(info, bit)

static X509 *LoadCert(const unsigned char *data, size_t len, CertFormat format)
{
	X509 *x509;
	BIO *bio = BIO_new_mem_buf(data, len);

	if (bio == NULL)
	{
		exit(1);
	}

	if (format == PEM)
	{
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	}
	else
	{
		x509 = d2i_X509_bio(bio, NULL);
	}

	BIO_free(bio);

	return x509;
}

static void Clear()
{
	errors[0] = 0;
	warnings[0] = 0;
	info[0] = 0;
}

static void CheckValidURL(const char *s, int n)
{
	/* RFC3986 */
	static char *reserved_chars = ":/?#[]@!$&'()*+,;=";
	static char *unreserved_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

	int i = 0;
	while (i < n)
	{
		if (s[i] == '%')
		{
			if (n - i < 3)
			{
				SetError(ERR_INVALID_URL);
				return;
			}
			if (!isxdigit(s[i+1]) || !isxdigit(s[i+2]))
			{
				SetError(ERR_INVALID_URL);
				return;
			}
			i+=3;
			continue;
		}
		if (strchr(reserved_chars, s[i]) == NULL && strchr(unreserved_chars, s[i]) == NULL)
		{
			SetError(ERR_INVALID_URL);
			return;
		}
		i++;
	}
	/* TODO: Check the rest of URL, like starting with "http://" */
}

static void CheckPrintableChars(const char *s, int n)
{
	int i;

	const unsigned char *s2 = (const unsigned char *)s;

	for (i = 0; i < n; i++)
	{
		if (s2[i] == '\0')
		{
			SetError(ERR_STRING_WITH_NUL);
		}
		else if (s2[i] < 32)
		{
			SetError(ERR_NON_PRINTABLE);
		}
		/* TODO: Check U+007F to U+009F */
	}
}

static void CheckNameEntryValid(const gnutls_x509_ava_st *ne)
{
	int i;

	if (ne->value_tag == 12) /* UTF8String */
	{
		size_t n1 = ne->value.size;
		size_t n2 = ne->value.size;
		char *s1 = (char *)ne->value.data;
		char *s2 = malloc(n2);
		char *ps2 = s2;

		/* reset iconv */
		iconv(iconv_utf8, NULL, 0, NULL, 0);

		if (iconv(iconv_utf8, &s1, &n1, &ps2, &n2) == (size_t) -1 || n1 != 0)
		{
			SetError(ERR_INVALID_ENCODING);
		}

		CheckPrintableChars((const char *)ne->value.data, ne->value.size);

		free(s2);
	}
	else if (ne->value_tag == 30) /* BMPString */
	{
		size_t n1 = ne->value.size;
		size_t n2 = ne->value.size*3;		/* U+FFFF is represented with 3 UTF-8 chars */
		char *s1 = (char *)ne->value.data;
		char *s2 = malloc(n2);
		char *ps2 = s2;

		/* reset iconv */
		iconv(iconv_ucs2, NULL, 0, NULL, 0);

		if (iconv(iconv_ucs2, &s1, &n1, &ps2, &n2) == (size_t) -1 || n1 != 0)
		{
			SetError(ERR_INVALID_ENCODING);
		}

		CheckPrintableChars(s2, ps2-s2);

		free(s2);
	}
	else if (ne->value_tag == 19) /* PrintableString */
	{
		int i;
		for (i = 0; i < ne->value.size; i++)
		{
			if (ne->value.data[i] == '\0')
			{
				SetError(ERR_STRING_WITH_NUL);
			}
			else if ((unsigned char)ne->value.data[i] < 32)
			{
				SetError(ERR_NON_PRINTABLE);
			}
			else if (!((ne->value.data[i] >= 'A' && ne->value.data[i] <= 'Z') ||
				(ne->value.data[i] >= 'a' && ne->value.data[i] <= 'z') ||
				(ne->value.data[i] >= '0' && ne->value.data[i] <= '9') ||
				(ne->value.data[i] == '\'') ||
				(ne->value.data[i] == '(') ||
				(ne->value.data[i] == ')') ||
				(ne->value.data[i] == '+') ||
				(ne->value.data[i] == ',') ||
				(ne->value.data[i] == '-') ||
				(ne->value.data[i] == '.') ||
				(ne->value.data[i] == '/') ||
				(ne->value.data[i] == ':') ||
				(ne->value.data[i] == '?') ||
				(ne->value.data[i] == ' ')))
			{
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else if (ne->value_tag == 22)    /* IA5String */
	{
		for (i = 0; i < ne->value.size; i++)
		{
			if (ne->value.data[i] == '\0')
			{
				SetError(ERR_STRING_WITH_NUL);
			}
			else if ((unsigned char)ne->value.data[i] < 32)
			{
				SetError(ERR_NON_PRINTABLE);
			}
			else if (((unsigned char)ne->value.data[i]) >= 128)
			{
				SetError(ERR_INVALID_ENCODING);
			}
		}
		SetWarning(WARN_IA5);
	}
	else if (ne->value_tag == 20)  /* TeletexString, T61String */
	{
		size_t n1 = ne->value.size;
		size_t n2 = ne->value.size*2;
		char *s1 = (char *)ne->value.data;
		char *s2 = malloc(n2);
		char *ps2 = s2;

		/* reset iconv */
		iconv(iconv_t61, NULL, 0, NULL, 0);

		if (iconv(iconv_t61, &s1, &n1, &ps2, &n2) == (size_t) -1 || n1 != 0)
		{
			SetError(ERR_INVALID_ENCODING);
		}

		CheckPrintableChars(s2, ps2-s2);

		free(s2);
	}
	else
	{
		SetInfo(INF_STRING_NOT_CHECKED);
	}

	/* It should be a DirectoryString, which is one of the below */
	if ((ne->value_tag != 19) &&      /* PrintableString */
		(ne->value_tag != 12) &&  /* UTF8String */
		(ne->value_tag != 20) &&  /* TeletexString, T61String */
		(ne->value_tag != 28) &&  /* UniversalString */
		(ne->value_tag != 30))    /* BMPString */
	{
		SetError(ERR_INVALID_TAG_TYPE);
	}
	else if ((ne->value_tag != 19) && (ne->value_tag != 12))
	{
		/* RFC5280 says it MUST be PrintableString or UTF8String, with exceptions. */
		SetWarning(WARN_NON_PRINTABLE_STRING);
	}

	return;
}

static void CheckDN(const gnutls_x509_dn_t dn)
{
	int irdn = 0;
	do
	{
		int iava = 0;
		gnutls_x509_ava_st ava;

		do
		{
			int ret = gnutls_x509_dn_get_rdn_ava(dn, irdn, iava, &ava);
			if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
			{
				break;
			}
			if (ret != 0)
			{
				SetError(ERR_INVALID);
				iava++;
				continue;
			}
			if (ava.value_tag != 16)
			{
				CheckNameEntryValid(&ava);
			}
			else
			{
				/* TODO: It's a sequence, we should go over it's members */
				SetInfo(INF_STRING_NOT_CHECKED);
			}
			iava++;
		}
		while(1);
		if (iava == 0)
		{
			break;
		}
		irdn++;
	}
	while(1);
}

static bool IsNameOIDPresent(const gnutls_x509_dn_t dn, const char *oid)
{
	int irdn = 0;
	do
	{
		int iava = 0;
		gnutls_x509_ava_st ava;

		do
		{
			int ret = gnutls_x509_dn_get_rdn_ava(dn, irdn, iava, &ava);
			if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
			{
				break;
			}
			if (ret != 0)
			{
				iava++;
				continue;
			}
			if (strcmp((const char *)ava.oid.data, oid) == 0)
			{
				return true;
			}
			iava++;
		}
		while(1);
		if (iava == 0)
		{
			break;
		}
		irdn++;
	}
	while(1);
	return false;
}

static bool IsValidLongerThan(const gnutls_x509_crt_t cert, int months)
{
	time_t from = gnutls_x509_crt_get_activation_time(cert);
	time_t to = gnutls_x509_crt_get_expiration_time(cert);

	if ((from == (time_t)-1) || (to == (time_t)-1))
	{
		SetError(ERR_INVALID);
		return false;
	}

	struct tm tm_from, tm_to;
	if (gmtime_r(&from, &tm_from) == NULL || gmtime_r(&to, &tm_to) == NULL)
	{
		SetError(ERR_DATE_OUT_OF_RANGE);
		return false;
	}

	int month_diff = (tm_to.tm_year - tm_from.tm_year) * 12
		+ tm_to.tm_mon - tm_from.tm_mon;
	if (month_diff > months)
	{
		return true;
	}
	if (month_diff < months)
	{
		return false;
	}
	if (tm_to.tm_mday < tm_from.tm_mday)
	{
		return false;
	}
	if (tm_to.tm_mday > tm_from.tm_mday)
	{
		return true;
	}
	if (tm_to.tm_hour < tm_from.tm_hour)
	{
		return false;
	}
	if (tm_to.tm_hour > tm_from.tm_hour)
	{
		return true;
	}
	if (tm_to.tm_min < tm_from.tm_min)
	{
		return false;
	}
	if (tm_to.tm_min > tm_from.tm_min)
	{
		return true;
	}
	if (tm_to.tm_sec < tm_from.tm_sec)
	{
		return false;
	}
	if (tm_to.tm_sec > tm_from.tm_sec)
	{
		return true;
	}
	return false;
}

static void CheckPolicy(X509 *x509, CertType type, gnutls_x509_dn_t subject)
{
	int idx = -1;
	bool bPolicyFound = false;
	do
	{
		int critical = -1;

		CERTIFICATEPOLICIES *policy = X509_get_ext_d2i(x509, NID_certificate_policies, &critical, &idx);

		if (policy == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				bPolicyFound = true;
				continue;
			}
			/* Not found */
			break;
		}
		bPolicyFound = true;

		for (int pi = 0; pi < sk_POLICYINFO_num(policy); pi++)
		{
			POLICYINFO *info = sk_POLICYINFO_value(policy, pi);

			char oid[80];
			OBJ_obj2txt(oid, sizeof(oid), info->policyid, 1);

			if (type == SubscriberCertificate)
			{
				/* Required by CAB base 9.3.1 */
				if (strcmp(oid, OIDCabDomainValidated) == 0
					&& (IsNameOIDPresent(subject, GNUTLS_OID_X520_ORGANIZATION_NAME)
						|| IsNameOIDPresent(subject, OIDStreetAddress)
						|| IsNameOIDPresent(subject, GNUTLS_OID_X520_LOCALITY_NAME)
						|| IsNameOIDPresent(subject, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME)
						|| IsNameOIDPresent(subject, GNUTLS_OID_X520_POSTALCODE)))
				{
					SetError(ERR_DOMAIN_WITH_ORG_OR_ADDRESS);
				}

				if (strcmp(oid, OIDCabIdentityValidated) == 0
					&& !(IsNameOIDPresent(subject, GNUTLS_OID_X520_ORGANIZATION_NAME)
						&& IsNameOIDPresent(subject, GNUTLS_OID_X520_LOCALITY_NAME)
						&& IsNameOIDPresent(subject, GNUTLS_OID_X520_COUNTRY_NAME)))
				{
					SetError(ERR_IDENTITY_WITHOUT_ORG_OR_ADDRESS);
				}
			}
		}
		CERTIFICATEPOLICIES_free(policy);
	}
	while(1);

	if (!bPolicyFound && type == SubscriberCertificate)
	{
		/* Required by CAB 9.3.4 */
		SetError(ERR_NO_POLICY);
	}
}

void check(const unsigned char *cert_buffer, size_t cert_len, CertFormat format, CertType type)
{
	gnutls_x509_dn_t issuer;
	gnutls_x509_dn_t subject;
	int i;
	int ret;
	size_t size = 81920;
	char buf[81920];
	gnutls_pk_algorithm_t pk_alg;
	unsigned int pk_bits;
	gnutls_x509_crt_t cert;
	gnutls_datum_t pem;
	X509 *x509;

	Clear();

	if (gnutls_x509_crt_init(&cert) != 0)
	{
		exit(1);
	}

	pem.data = (unsigned char *)cert_buffer;
	pem.size = cert_len;

	if (gnutls_x509_crt_import(cert, &pem, format == PEM ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER) != 0)
	{
		SetError(ERR_INVALID);
		return;
	}

	x509 = LoadCert(cert_buffer, cert_len, format);
	if (x509 == NULL)
	{
		SetError(ERR_INVALID);
		return;
	}

	ret = gnutls_x509_crt_get_version(cert);
	if (ret < 0)
	{
		SetError(ERR_INVALID);
	}
	if (ret != 3)
	{
		SetError(ERR_NOT_VERSION3);
	}

	gnutls_x509_crt_get_issuer(cert, &issuer);
	CheckDN(issuer);

	/* Required by CAB base 9.1.3 */
	if (!IsNameOIDPresent(issuer, GNUTLS_OID_X520_ORGANIZATION_NAME))
	{
		SetError(ERR_ISSUER_ORG_NAME);
	}

	/* Required by CAB base 9.1.4 */
	if (!IsNameOIDPresent(issuer, GNUTLS_OID_X520_COUNTRY_NAME))
	{
		SetError(ERR_ISSUER_COUNTRY);
	}

	
	gnutls_x509_crt_get_subject(cert, &subject);
	CheckDN(subject);

	/* Prohibited in CAB base 9.2.4b */
	if (!IsNameOIDPresent(subject, GNUTLS_OID_X520_ORGANIZATION_NAME)
		&& IsNameOIDPresent(subject, OIDStreetAddress))
	{
		SetError(ERR_SUBJECT_ADDR);
	}

	/* Required in CAB base 9.2.4c and 9.2.4d */
	if (IsNameOIDPresent(subject, GNUTLS_OID_X520_ORGANIZATION_NAME)
		&& !IsNameOIDPresent(subject, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME)
		&& !IsNameOIDPresent(subject, GNUTLS_OID_X520_LOCALITY_NAME))
	{
		SetError(ERR_SUBJECT_ORG_NO_PLACE);
	}

	/* Prohibited in CAB base 9.2.4c or 9.2.4d */
	if (!IsNameOIDPresent(subject, GNUTLS_OID_X520_ORGANIZATION_NAME)
		&& (IsNameOIDPresent(subject, GNUTLS_OID_X520_LOCALITY_NAME)
			|| IsNameOIDPresent(subject, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME)))
	{
		SetError(ERR_SUBJECT_NO_ORG_PLACE);
	}

	/* Required by CAB base 9.2.5 */
	if (IsNameOIDPresent(subject, GNUTLS_OID_X520_ORGANIZATION_NAME)
		&& !IsNameOIDPresent(subject, GNUTLS_OID_X520_COUNTRY_NAME))
	{
		SetError(ERR_SUBJECT_COUNTRY);
	}

	CheckPolicy(x509, type, subject);

	/* Required by CAB base 9.2.1 */
	/* It's not clear if this should also apply to CAs, the CAB base
	 * document doesn't exclude them, but I think it shouldn't apply to CAs. */
	unsigned int critical;
	ret = gnutls_x509_crt_get_extension_by_oid(cert, OIDSubjectAltName, 0, NULL, &size, &critical);
	if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	{
		if (type == SubscriberCertificate)
		{
			SetError(ERR_NO_SUBJECT_ALT_NAME);
		}
	}
	else if (ret != 0)
	{
		SetError(ERR_INVALID);
	}

	/* Deprecated in CAB base 9.2.2 */
	if (IsNameOIDPresent(subject, GNUTLS_OID_X520_COMMON_NAME))
	{
		SetInfo(INF_SUBJECT_CN);
	}

	pk_alg = gnutls_x509_crt_get_pk_algorithm(cert, &pk_bits);
	if (pk_alg < 0)
	{
		SetError(ERR_INVALID);
	}

	i = 0;
	while (1)
	{
		size = sizeof(buf);
		int ret = gnutls_x509_crt_get_crl_dist_points(cert, i, buf, &size, NULL, NULL);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		{
			break;
		}
		if (ret < 0)
		{
			SetError(ERR_INVALID);
			break;
		}
		if (ret != GNUTLS_SAN_URI)
		{
			SetInfo(INF_CRL_NOT_URL);
		}
		CheckValidURL(buf, size);
		i++;
	}

	if (type == SubscriberCertificate)
	{
		/* CAB 9.4.1 */
		if (IsValidLongerThan(cert, 39))
		{
			SetWarning(WARN_LONGER_39_MONTHS);
		}
		if (IsValidLongerThan(cert, 60))
		{
			SetWarning(ERR_LONGER_60_MONTHS);
		}
	}

	gnutls_x509_crt_deinit(cert);
	X509_free(x509);
}

void check_init()
{
	int ret;
	if ((ret = gnutls_global_init()) < 0)
	{
		fprintf(stderr, "gnutls_global_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	OpenSSL_add_all_algorithms();

	iconv_utf8 = iconv_open("utf-8", "utf-8");
	iconv_ucs2 = iconv_open("utf-8", "ucs-2be");
	iconv_t61 = iconv_open("utf-8", "CSISO103T618BIT");
}

void check_finish()
{
	iconv_close(iconv_utf8);
	iconv_close(iconv_ucs2);
	iconv_close(iconv_t61);
	gnutls_global_deinit();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

