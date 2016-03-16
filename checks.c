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
static const char *OIDpostalCode = "2.5.4.17";
static const char *OIDCabDomainValidated = "2.23.140.1.2.1";
static const char *OIDCabIdentityValidated = "2.23.140.1.2.2";
static const char *OIDSubjectAltName = "2.5.29.17";

static ASN1_OBJECT *obj_organizationName;
static ASN1_OBJECT *obj_StreetAddress;
static ASN1_OBJECT *obj_localityName;
static ASN1_OBJECT *obj_stateOrProvinceName;
static ASN1_OBJECT *obj_postalCode;
static ASN1_OBJECT *obj_countryName;
static ASN1_OBJECT *obj_commonName;

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

static X509 *LoadCert(unsigned char *data, size_t len, CertFormat format)
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

/*
 * Check that the string contains pritable characters.
 * The input is a valid UTF-8 string.
 */
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

static void CheckNameEntryValid(X509_NAME_ENTRY *ne)
{
	int i;

	ASN1_STRING *data = X509_NAME_ENTRY_get_data(ne);
	ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);
	int nid = OBJ_obj2nid(obj);

	if (data->type == V_ASN1_UTF8STRING)
	{
		size_t n1 = data->length;
		size_t n2 = data->length;
		char *s1 = (char *)data->data;
		char *s2 = malloc(n2);
		char *ps2 = s2;

		/* reset iconv */
		iconv(iconv_utf8, NULL, 0, NULL, 0);

		if (iconv(iconv_utf8, &s1, &n1, &ps2, &n2) == (size_t) -1 || n1 != 0)
		{
			SetError(ERR_INVALID_ENCODING);
		}
		else
		{
			CheckPrintableChars((const char *)data->data, data->length);
		}

		free(s2);
	}
	else if (data->type == V_ASN1_BMPSTRING)
	{
		size_t n1 = data->length;
		size_t n2 = data->length*3;		/* U+FFFF is represented with 3 UTF-8 chars */
		char *s1 = (char *)data->data;
		char *s2 = malloc(n2);
		char *ps2 = s2;

		/* reset iconv */
		iconv(iconv_ucs2, NULL, 0, NULL, 0);

		if (iconv(iconv_ucs2, &s1, &n1, &ps2, &n2) == (size_t) -1 || n1 != 0)
		{
			SetError(ERR_INVALID_ENCODING);
		}
		else
		{
			CheckPrintableChars(s2, ps2-s2);
		}

		free(s2);
	}
	else if (data->type == V_ASN1_PRINTABLESTRING)
	{
		int i;
		for (i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				SetError(ERR_STRING_WITH_NUL);
			}
			else if (data->data[i] < 32)
			{
				SetError(ERR_NON_PRINTABLE);
			}
			else if (!((data->data[i] >= 'A' && data->data[i] <= 'Z') ||
				(data->data[i] >= 'a' && data->data[i] <= 'z') ||
				(data->data[i] >= '0' && data->data[i] <= '9') ||
				(data->data[i] == '\'') ||
				(data->data[i] == '(') ||
				(data->data[i] == ')') ||
				(data->data[i] == '+') ||
				(data->data[i] == ',') ||
				(data->data[i] == '-') ||
				(data->data[i] == '.') ||
				(data->data[i] == '/') ||
				(data->data[i] == ':') ||
				(data->data[i] == '?') ||
				(data->data[i] == ' ')))
			{
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else if (data->type == V_ASN1_IA5STRING)
	{
		for (i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				SetError(ERR_STRING_WITH_NUL);
			}
			else if (data->data[i] < 32)
			{
				SetError(ERR_NON_PRINTABLE);
			}
			else if (data->data[i] >= 128)
			{
				SetError(ERR_INVALID_ENCODING);
			}
		}
		SetWarning(WARN_IA5);
	}
	else if (data->type == V_ASN1_T61STRING)  /* TeletexString, T61String */
	{
		size_t n1 = data->length;
		size_t n2 = data->length*2;
		char *s1 = (char *)data->data;
		char *s2 = malloc(n2);
		char *ps2 = s2;

		/* reset iconv */
		iconv(iconv_t61, NULL, 0, NULL, 0);

		if (iconv(iconv_t61, &s1, &n1, &ps2, &n2) == (size_t) -1 || n1 != 0)
		{
			SetError(ERR_INVALID_ENCODING);
		}
		else
		{
			CheckPrintableChars(s2, ps2-s2);
		}

		free(s2);
	}
	else
	{
		SetInfo(INF_STRING_NOT_CHECKED);
	}

	/* It should be a DirectoryString, which is one of the below */
	if ((data->type != V_ASN1_PRINTABLESTRING) &&
		(data->type != V_ASN1_UTF8STRING) &&
		(data->type != V_ASN1_T61STRING) &&
		(data->type != V_ASN1_UNIVERSALSTRING) &&
		(data->type != V_ASN1_BMPSTRING))
	{
		SetError(ERR_INVALID_TAG_TYPE);
	}
	else if ((data->type != V_ASN1_PRINTABLESTRING) && (data->type != V_ASN1_UTF8STRING))
	{
		/* RFC5280 says it MUST be PrintableString or UTF8String, with exceptions. */
		SetWarning(WARN_NON_PRINTABLE_STRING);
	}

	if (nid == NID_countryName)
	{
		if (data->type != V_ASN1_PRINTABLESTRING)
		{
			SetError(ERR_INVALID_TAG_TYPE);
		}
		if (data->length != 2)
		{
			SetError(ERR_COUNTRY_SIZE);
		}
	}

	return;
}

static void CheckDN(X509_NAME *dn)
{
	for (int i = 0; i < X509_NAME_entry_count(dn); i++)
	{
		X509_NAME_ENTRY *ne = X509_NAME_get_entry(dn, i);
		ASN1_STRING *data = X509_NAME_ENTRY_get_data(ne);

		if (data->type != V_ASN1_SEQUENCE)
		{
			CheckNameEntryValid(ne);
		}
		else
		{
			/* TODO: It's a sequence, we should go over it's members */
			SetInfo(INF_STRING_NOT_CHECKED);
		}
	}
}

static bool IsNameObjPresent(X509_NAME *dn, ASN1_OBJECT *obj)
{
	return X509_NAME_get_index_by_OBJ(dn, obj, -1) >= 0;
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

static void CheckPolicy(X509 *x509, CertType type, X509_NAME *subject)
{
	int idx = -1;
	bool bPolicyFound = false;
	bool bHaveAnyPolicy = false;
	size_t policies = 0;
	bool DomainValidated = false;
	bool IdentityValidated = false;

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

		policies += sk_POLICYINFO_num(policy);

		for (int pi = 0; pi < sk_POLICYINFO_num(policy); pi++)
		{
			POLICYINFO *info = sk_POLICYINFO_value(policy, pi);

			char oid[80];
			OBJ_obj2txt(oid, sizeof(oid), info->policyid, 1);

			if (OBJ_obj2nid(info->policyid) == NID_any_policy)
			{
				bHaveAnyPolicy = true;
			}

			if (type == SubscriberCertificate)
			{
				/* Required by CAB base 9.3.1 */
				if (strcmp(oid, OIDCabDomainValidated) == 0)
				{
					DomainValidated = true;
					if (IsNameObjPresent(subject, obj_organizationName)
						|| IsNameObjPresent(subject, obj_StreetAddress)
						|| IsNameObjPresent(subject, obj_localityName)
						|| IsNameObjPresent(subject, obj_stateOrProvinceName)
						|| IsNameObjPresent(subject, obj_postalCode))
					{
						SetError(ERR_DOMAIN_WITH_ORG_OR_ADDRESS);
					}
				}

				if (strcmp(oid, OIDCabIdentityValidated) == 0)
				{
					IdentityValidated = true;
					if (!(IsNameObjPresent(subject, obj_organizationName)
						&& IsNameObjPresent(subject, obj_localityName)
						&& IsNameObjPresent(subject, obj_countryName)))
					{
						SetError(ERR_IDENTITY_WITHOUT_ORG_OR_ADDRESS);
					}
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

	if (bHaveAnyPolicy && policies > 1)
	{
		SetError(ERR_ANY_POLICY_WITH_OTHER);
	}

	if (type == SubscriberCertificate && !DomainValidated && !IdentityValidated)
	{
		SetInfo(INF_UNKNOWN_VALIDATION);
	}
}

static char *asn1_time_as_string(ASN1_TIME *time)
{
	char *s = malloc(time->length+1);
	if (s == NULL)
	{
		exit(1);
	}
	strncpy(s, (char *)time->data, time->length);
	s[time->length] = '\0';
	if (strlen(s) != time->length)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
	return s;
}

static void time_str_to_tm(char *s, bool general, struct tm *tm)
{
	for (int i = 0; i < strlen(s)-1; i++)
	{
		if (isdigit(s[i]) == 0)
		{
			SetError(ERR_INVALID_TIME_FORMAT);
			return;
		}
	}
	int i = 0;
	if (general)
	{
		tm->tm_year = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + s[3] - '0' - 1900;
		i += 4;

		if (tm->tm_year < 150 || tm->tm_year >= 50)
		{
			SetError(ERR_INVALID_TIME_FORMAT);
		}
	}
	else
	{
		int year = (s[2] - '0') * 10 + s[3] - '0';
		if (year < 50)
		{
			tm->tm_year = 100 + year;
		}
		else
		{
			tm->tm_year = year;
		}
		i += 2;
	}
	tm->tm_mon = (s[i] - '0') * 10 + s[i+1] - '0' - 1;
	i += 2;
	if (tm->tm_mon > 11)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
	tm->tm_mday = (s[i] - '0') * 10 + s[i+1] - '0' - 1;
	i += 2;
	if (tm->tm_mday == 0 || tm->tm_mday > 31)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}

	if ((tm->tm_mon == 3 || tm->tm_mon == 5 || tm->tm_mon == 8 || tm->tm_mon == 10)
		&& tm->tm_mday > 30)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
	if (tm->tm_mon == 1)
	{
		if (((tm->tm_year % 4) == 0 && (tm->tm_year % 100) != 0)
			|| (((tm->tm_year + 1900) % 400) == 0))
		{
			if (tm->tm_mday > 29)
			{
				SetError(ERR_INVALID_TIME_FORMAT);
			}
		}
		else
		{
			if (tm->tm_mday > 28)
			{
				SetError(ERR_INVALID_TIME_FORMAT);
			}
		}
	}

	tm->tm_hour = (s[i] - '0') * 10 + s[i+1] - '0' - 1;
	i += 2;
	if (tm->tm_hour > 23)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
	tm->tm_min = (s[i] - '0') * 10 + s[i+1] - '0' - 1;
	i += 2;
	if (tm->tm_min > 59)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
	tm->tm_sec = (s[i] - '0') * 10 + s[i+1] - '0' - 1;
	if (tm->tm_sec > 60) /* including leap seconds */
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
}

static void asn1_time_to_tm(ASN1_TIME *time, bool general, struct tm *tm)
{
	char *s = asn1_time_as_string(time);
	if (general)
	{
		if (strlen(s) != 15)
		{
			SetError(ERR_INVALID_TIME_FORMAT);
		}
	}
	else
	{
		if (strlen(s) != 13)
		{
			SetError(ERR_INVALID_TIME_FORMAT);
		}
	}
	if (s[strlen(s)-1] != 'Z')
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}
	time_str_to_tm(s, general, tm);
	free(s);
}

static void CheckTime(X509 *x509)
{
	ASN1_TIME *before = X509_get_notBefore(x509);
	ASN1_TIME *after = X509_get_notAfter(x509);
	struct tm tm_before;
	struct tm tm_after;

	if (before->type == V_ASN1_GENERALIZEDTIME)
	{
		asn1_time_to_tm(before, true, &tm_before);
	}
	else if (before->type == V_ASN1_UTCTIME)
	{
		asn1_time_to_tm(before, false, &tm_before);
	}
	else
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}

	if (after->type == V_ASN1_GENERALIZEDTIME)
	{
		asn1_time_to_tm(after, true, &tm_after);
	}
	else if (after->type == V_ASN1_UTCTIME)
	{
		asn1_time_to_tm(after, false, &tm_after);
	}
	else
	{
		SetError(ERR_INVALID_TIME_FORMAT);
	}

	if (GetBit(errors, ERR_INVALID_TIME_FORMAT))
	{
		return;
	}
}

void check(unsigned char *cert_buffer, size_t cert_len, CertFormat format, CertType type)
{
	X509_NAME *issuer;
	X509_NAME *subject;
	int i;
	int ret;
	size_t size = 81920;
	char buf[81920];
	gnutls_pk_algorithm_t pk_alg;
	unsigned int pk_bits;
	gnutls_x509_crt_t cert;
	gnutls_datum_t pem;
	X509 *x509;
	int ca;

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

	ca = X509_check_ca(x509);
	if (ca > 0 && type == SubscriberCertificate)
	{
		SetWarning(WARN_CHECKED_AS_SUBSCRIBER);
	}
	else if (ca == 0 && type != SubscriberCertificate)
	{
		SetWarning(WARN_CHECKED_AS_CA);
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

	issuer = X509_get_issuer_name(x509);
	if (issuer == NULL)
	{
		SetError(ERR_INVALID);
		return;
	}
	CheckDN(issuer);

	/* Required by CAB base 9.1.3 */
	if (!IsNameObjPresent(issuer, obj_organizationName))
	{
		SetError(ERR_ISSUER_ORG_NAME);
	}

	/* Required by CAB base 9.1.4 */
	if (!IsNameObjPresent(issuer, obj_countryName))
	{
		SetError(ERR_ISSUER_COUNTRY);
	}

	
	subject = X509_get_subject_name(x509);
	if (subject == NULL)
	{
		SetError(ERR_INVALID);
		return;
	}
	CheckDN(subject);

	/* Prohibited in CAB base 9.2.4b */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& IsNameObjPresent(subject, obj_StreetAddress))
	{
		SetError(ERR_SUBJECT_ADDR);
	}

	/* Required in CAB base 9.2.4c and 9.2.4d */
	if (IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_stateOrProvinceName)
		&& !IsNameObjPresent(subject, obj_localityName))
	{
		SetError(ERR_SUBJECT_ORG_NO_PLACE);
	}

	/* Prohibited in CAB base 9.2.4c or 9.2.4d */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& (IsNameObjPresent(subject, obj_localityName)
			|| IsNameObjPresent(subject, obj_stateOrProvinceName)))
	{
		SetError(ERR_SUBJECT_NO_ORG_PLACE);
	}

	/* Required by CAB base 9.2.5 */
	if (IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_countryName))
	{
		SetError(ERR_SUBJECT_COUNTRY);
	}

	CheckPolicy(x509, type, subject);

	/* Required by CAB base 7.1.4.2.1 */
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

	/* Deprecated in CAB base 7.1.4.2.2 */
	if (IsNameObjPresent(subject, obj_commonName))
	{
		if (type == SubscriberCertificate)
		{
			SetInfo(INF_SUBJECT_CN);
		}
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
		else
		{
			CheckValidURL(buf, size);
		}
		i++;
	}

	CheckTime(x509);

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

	obj_organizationName = OBJ_nid2obj(NID_organizationName);
	obj_localityName = OBJ_nid2obj(NID_localityName);
	obj_stateOrProvinceName = OBJ_nid2obj(NID_stateOrProvinceName);
	obj_countryName = OBJ_nid2obj(NID_countryName);
	obj_commonName = OBJ_nid2obj(NID_commonName);

	/* Those get leaked, unsure how to clean them up. */
	obj_StreetAddress = OBJ_txt2obj(OIDStreetAddress, 1);
	obj_postalCode = OBJ_txt2obj(OIDpostalCode, 1);
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

