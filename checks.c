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
#include <stdint.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "checks.h"
#include "asn1_time.h"

static iconv_t iconv_utf8;
static iconv_t iconv_ucs2;
static iconv_t iconv_t61;
static iconv_t iconv_ucs4;

static const char *OIDStreetAddress = "2.5.4.9";
static const char *OIDpostalCode = "2.5.4.17";

#if OPENSSL_VERSION_NUMBER < 0x1000200FL
static const char *OIDjurisdictionCountryName = "1.3.6.1.4.1.311.60.2.1.3";
#endif

static const char *OIDCabDomainValidated = "2.23.140.1.2.1";
static const char *OIDCabOrganizationIdentityValidated = "2.23.140.1.2.2";
static const char *OIDCabIndividualIdentityValidated = "2.23.140.1.2.3";
static const char *OIDCabExtendedValidation = "2.23.140.1.3";


static ASN1_OBJECT *obj_organizationName;
static ASN1_OBJECT *obj_StreetAddress;
static ASN1_OBJECT *obj_localityName;
static ASN1_OBJECT *obj_stateOrProvinceName;
static ASN1_OBJECT *obj_postalCode;
static ASN1_OBJECT *obj_countryName;
static ASN1_OBJECT *obj_commonName;
static ASN1_OBJECT *obj_givenName;
static ASN1_OBJECT *obj_surname;
static ASN1_OBJECT *obj_businessCategory;
static ASN1_OBJECT *obj_serialNumber;
static ASN1_OBJECT *obj_jurisdictionCountryName;

uint32_t errors[2];
uint32_t warnings[1];
uint32_t info[1];

static void SetBit(uint32_t *val, int bit)
{
	val[bit/(sizeof(uint32_t)*8)] |= (1 << (bit % (sizeof(int)*8)));
}

int GetBit(uint32_t *val, int bit)
{
	return (val[bit/(sizeof(uint32_t)*8)] & (1 << (bit % (sizeof(uint32_t)*8)))) != 0;
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
	errors[1] = 0;
	warnings[0] = 0;
	info[0] = 0;
}

static void CheckValidURL(const unsigned char *s, int n)
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
 * The input is in internal UCS-4 notation.
 *
 * Returns true when no error found and false when an error was found.
 * It also updates the errors.
 */
static bool CheckPrintableChars(const uint32_t *s, int n)
{
	int i;
	bool ret = true;

	for (i = 0; i < n; i++)
	{
		if (s[i] == '\0')
		{
			SetError(ERR_STRING_WITH_NUL);
			ret = false;
		}
		else if (s[i] < 32)
		{
			SetError(ERR_NON_PRINTABLE);
			ret = false;
		}
		if (s[i] >= 0x7F && s[i] <= 0x9F)
		{
			SetError(ERR_NON_PRINTABLE);
			ret = false;
		}
	}
	return ret;
}

/*
 * Checks that a string is valid
 *
 * Returns true when no error was found and false when an error was found
 * It also updates the error
 * When no error was found it will fill in char_len with the number of
 * characters in the string, not the number of octets.
 */
static bool CheckStringValid(ASN1_STRING *data, size_t *char_len)
{
	char *utf8 = NULL;
	size_t utf8_len;
	bool ret = true;

	if (data->type == V_ASN1_UTF8STRING)
	{
		size_t n = data->length;
		size_t utf8_size = data->length;
		char *s = (char *)data->data;
		utf8 = malloc(utf8_size);
		char *pu = utf8;

		/* reset iconv */
		iconv(iconv_utf8, NULL, 0, NULL, 0);

		if (iconv(iconv_utf8, &s, &n, &pu, &utf8_size) == (size_t) -1 || n != 0)
		{
			ret = false;
			SetError(ERR_INVALID_ENCODING);
		}
		utf8_len = data->length;
	}
	else if (data->type == V_ASN1_BMPSTRING)
	{
		size_t n = data->length;
		size_t utf8_size = data->length*3;		/* U+FFFF is represented with 3 UTF-8 chars */
		char *s = (char *)data->data;
		utf8 = malloc(utf8_size);
		char *pu = utf8;

		/* reset iconv */
		iconv(iconv_ucs2, NULL, 0, NULL, 0);

		if (iconv(iconv_ucs2, &s, &n, &pu, &utf8_size) == (size_t) -1 || n != 0)
		{
			ret = false;
			SetError(ERR_INVALID_ENCODING);
		}
		utf8_len = pu - utf8;
	}
	else if (data->type == V_ASN1_PRINTABLESTRING)
	{
		for (int i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				ret = false;
				SetError(ERR_STRING_WITH_NUL);
			}
			else if (data->data[i] < 32)
			{
				ret = false;
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
				ret = false;
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else if (data->type == V_ASN1_IA5STRING || data->type == V_ASN1_VISIBLESTRING)
	{
		/*
		 * IA5String's valid range is 0x00 - 0x7F,
		 * VisibleString restricts it to the visible ones: 0x20 - 0x7E
		 * We restrict both to the VisibleString range.
		 */
		for (int i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				ret = false;
				SetError(ERR_STRING_WITH_NUL);
			}
			else if (data->data[i] < 32)
			{
				ret = false;
				SetError(ERR_NON_PRINTABLE);
			}
			else if (data->data[i] >= 127)
			{
				ret = false;
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else if (data->type == V_ASN1_T61STRING)  /* TeletexString, T61String */
	{
		size_t n = data->length;
		size_t utf8_size = data->length*2;
		char *s = (char *)data->data;
		utf8 = malloc(utf8_size);
		char *pu = utf8;

		/* reset iconv */
		iconv(iconv_t61, NULL, 0, NULL, 0);

		if (iconv(iconv_t61, &s, &n, &pu, &utf8_size) == (size_t) -1 || n != 0)
		{
			ret = false;
			SetError(ERR_INVALID_ENCODING);
		}
		utf8_len = pu - utf8;
	}
	else
	{
		SetInfo(INF_STRING_NOT_CHECKED);
		return 0;
	}

	if (!GetBit(errors, ERR_INVALID_ENCODING))
	{

		if (utf8 != NULL)
		{
			/* reset iconv */
			iconv(iconv_ucs4, NULL, 0, NULL, 0);

			char *s = utf8;
			size_t n = utf8_len;
			size_t ucs4_size = utf8_len * 4;
			uint32_t *ucs4 = malloc(ucs4_size);
			char *pu = (char *)ucs4;

			if (iconv(iconv_ucs4, &s, &n, (char **)&pu, &ucs4_size) == (size_t) -1 || n != 0)
			{
				/* Shouldn't happen. */
				SetError(ERR_INVALID_ENCODING);
				free(utf8);
				free(ucs4);
				return false;
			}
			else
			{
				*char_len = (pu - (char *)ucs4) / 4;
				if (!CheckPrintableChars(ucs4, *char_len))
				{
					ret = false;
				}
			}
			free(ucs4);
		}
		else
		{
			*char_len = data->length;
		}
	}
	free(utf8);
	return ret;
}

static void CheckNameEntryValid(X509_NAME_ENTRY *ne)
{
	ASN1_STRING *data = X509_NAME_ENTRY_get_data(ne);
	ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);
	int nid = OBJ_obj2nid(obj);
	size_t char_len;

	if (CheckStringValid(data, &char_len))
	{
		if (nid == NID_countryName)
		{
			if (char_len != 2)
			{
				SetError(ERR_COUNTRY_SIZE);
			}
		}
		else if (nid == NID_commonName)
		{
			if (char_len > ub_common_name)
			{
				SetError(ERR_COMMON_NAME_SIZE);
			}
		}
		else if (nid == NID_localityName)
		{
			if (char_len > ub_locality_name)
			{
				SetError(ERR_LOCALITY_NAME_SIZE);
			}
		}
		else if (nid == NID_stateOrProvinceName)
		{
			if (char_len > ub_state_name)
			{
				SetError(ERR_STATE_NAME_SIZE);
			}
		}
		else if (nid == NID_organizationName)
		{
			if (char_len > ub_organization_name)
			{
				SetError(ERR_ORGANIZATION_NAME_SIZE);
			}
		}
		else if (nid == NID_organizationalUnitName)
		{
			if (char_len > ub_organization_unit_name)
			{
				SetError(ERR_ORGANIZATIONAL_UNIT_NAME_SIZE);
			}
		}
		else if (nid == NID_serialNumber)
		{
			if (char_len > 64)
			{
				SetError(ERR_SERIAL_NUMBER_SIZE);
			}
		}
		else if (OBJ_cmp(obj, obj_jurisdictionCountryName) == 0)
		{
			if (char_len != 2)
			{
				SetError(ERR_COUNTRY_SIZE);
			}
		}
		else if (nid == NID_businessCategory)
		{
			/* TODO: We should check it's one of the valid entries */
		}
		else if (OBJ_cmp(obj, obj_postalCode) == 0)
		{
			if (char_len > 16)
			{
				SetError(ERR_POSTAL_CODE_SIZE);
			}
		}
		else if (OBJ_cmp(obj, obj_StreetAddress) == 0)
		{
			/*
			 * There might not be a limit, it's not clear
			 * to me currently.
			 */
			if (char_len > 30)
			{
				SetError(ERR_STREET_ADDRESS_SIZE);
			}
		}
		else if (nid == NID_dnQualifier)
		{
			/* Doesn't seem to have a limit */
		}
		else if (nid == NID_pkcs9_emailAddress)
		{
			if (char_len > 255)
			{
				SetError(ERR_EMAIL_SIZE);
			}
		}
		else if (nid == NID_givenName)
		{
			if (char_len > 16)
			{
				/*
				 * This seems rather short, but it's what
				 * RFC5280 says.
				 */
				SetError(ERR_GIVEN_NAME_SIZE);
			}
		}
		else if (nid == NID_surname)
		{
			if (char_len > 40)
			{
				SetError(ERR_SURNAME_SIZE);
			}
		}
		else
		{
			SetInfo(INF_NAME_ENTRY_LENGTH_NOT_CHECKED);
		}
	}

	if (nid == NID_pkcs9_emailAddress)
	{
		if (data->type != V_ASN1_IA5STRING)
		{
			SetError(ERR_INVALID_NAME_ENTRY_TYPE);
		}
	}
	else
	{
		/* It should be a DirectoryString, which is one of the below */
		if ((data->type != V_ASN1_PRINTABLESTRING) &&
			(data->type != V_ASN1_UTF8STRING) &&
			(data->type != V_ASN1_T61STRING) &&
			(data->type != V_ASN1_UNIVERSALSTRING) &&
			(data->type != V_ASN1_BMPSTRING))
		{
			SetError(ERR_INVALID_NAME_ENTRY_TYPE);
		}
		else if ((data->type != V_ASN1_PRINTABLESTRING) && (data->type != V_ASN1_UTF8STRING))
		{
			/* RFC5280 says it MUST be PrintableString or UTF8String, with exceptions. */
			SetWarning(WARN_NON_PRINTABLE_STRING);
		}
	}

	if (nid == NID_countryName && data->type != V_ASN1_PRINTABLESTRING)
	{
		SetError(ERR_INVALID_NAME_ENTRY_TYPE);
	}
	if (nid == NID_dnQualifier && data->type != V_ASN1_PRINTABLESTRING)
	{
		SetError(ERR_INVALID_NAME_ENTRY_TYPE);
	}
	if (nid == NID_serialNumber && data->type != V_ASN1_PRINTABLESTRING)
	{
		SetError(ERR_INVALID_NAME_ENTRY_TYPE);
	}

	return;
}

static void CheckDisplayText(ASN1_STRING *s)
{
	size_t char_len;

	if (s->type != V_ASN1_IA5STRING && s->type != V_ASN1_VISIBLESTRING &&
		s->type != V_ASN1_BMPSTRING && s->type != V_ASN1_UTF8STRING)
	{
		SetError(ERR_INVALID_DISPLAY_TEXT_TYPE);
	}
	if (CheckStringValid(s, &char_len))
	{
		if (char_len > 200)
		{
			SetError(ERR_INVALID_DISPLAY_TEXT_LENGTH);
		}
	}
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

static bool IsValidLongerThan(struct tm tm_from, struct tm tm_to, int months)
{
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
	bool DomainValidated = false;
	bool OrganizationValidated = false;
	bool IndividualValidated = false;
	bool EVValidated = false;

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
				if (strcmp(oid, OIDCabDomainValidated) == 0
					|| strcmp(oid, "2.16.840.1.114413.1.7.23.1") == 0
					|| strcmp(oid, "2.16.840.1.114414.1.7.23.1") == 0)
				{
					DomainValidated = true;
					/* Required by CAB base 7.1.6.1 */
					if (IsNameObjPresent(subject, obj_organizationName))
					{
						SetError(ERR_DOMAIN_WITH_ORG);
					}
					if (IsNameObjPresent(subject, obj_StreetAddress))
					{
						SetError(ERR_DOMAIN_WITH_STREET);
					}
					if (IsNameObjPresent(subject, obj_localityName))
					{
						SetError(ERR_DOMAIN_WITH_LOCALITY);
					}
					if (IsNameObjPresent(subject, obj_stateOrProvinceName))
					{
						SetError(ERR_DOMAIN_WITH_STATE);
					}
					if (IsNameObjPresent(subject, obj_postalCode))
					{
						SetError(ERR_DOMAIN_WITH_POSTAL);
					}
				}

				if (strcmp(oid, OIDCabOrganizationIdentityValidated) == 0
					|| strcmp(oid, "2.16.840.1.114412.1.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.4788.2.200.1") == 0
					|| strcmp(oid, "2.16.840.1.114413.1.7.23.2") == 0
					|| strcmp(oid, "2.16.528.1.1003.1.2.5.6") == 0
					|| strcmp(oid, "1.3.6.1.4.1.8024.0.2.100.1.1") == 0
					|| strcmp(oid, "2.16.840.1.114414.1.7.23.2") == 0
					|| strcmp(oid, "2.16.792.3.0.3.1.1.2") == 0)
				{
					OrganizationValidated = true;
					/* Required by CAB base 7.1.6.1 */
					if (!IsNameObjPresent(subject, obj_organizationName))
					{
						SetError(ERR_ORGANIZATION_WITHOUT_ORG);
					}
					if (!IsNameObjPresent(subject, obj_localityName))
					{
						SetError(ERR_ORGANIZATION_WITHOUT_LOCALITY);
					}
					if (!IsNameObjPresent(subject, obj_countryName))
					{
						SetError(ERR_ORGANIZATION_WITHOUT_COUNTRY);
					}
				}

				if (strcmp(oid, OIDCabIndividualIdentityValidated) == 0)
				{
					IndividualValidated = true;
					/* Required by CAB base 7.1.6.1 */
					if (!IsNameObjPresent(subject, obj_organizationName)
						|| !(IsNameObjPresent(subject, obj_givenName) && IsNameObjPresent(subject, obj_surname)))
					{
						SetError(ERR_INDIVDUAL_WITHOUT_NAME);
					}
					if (!IsNameObjPresent(subject, obj_countryName))
					{
						SetError(ERR_INDIVDUAL_WITHOUT_COUNTRY);
					}
				}

				if (strcmp(oid, OIDCabExtendedValidation) == 0
					|| strcmp(oid, "2.16.840.1.114412.2.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.4788.2.202.1") == 0
					|| strcmp(oid, "2.16.840.1.114413.1.7.23.3") == 0
					|| strcmp(oid, "1.3.6.1.4.1.8024.0.2.100.1.2") == 0
					|| strcmp(oid, "2.16.840.1.114414.1.7.23.3") == 0
					|| strcmp(oid, "2.16.756.1.89.1.2.1.1") == 0
					|| strcmp(oid, "2.16.792.3.0.3.1.1.5") == 0
					|| strcmp(oid, "1.3.6.1.4.1.6449.1.2.1.5.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.36305.2") == 0)
				{
					EVValidated = true;
					/* 9.2.1 */
					if (!IsNameObjPresent(subject, obj_organizationName))
					{
						SetError(ERR_EV_WITHOUT_ORGANIZATION);
					}
					/* 9.2.4 */
					if (!IsNameObjPresent(subject, obj_businessCategory))
					{
						SetError(ERR_EV_WITHOUT_BUSINESS);
					}
					/* 9.2.5 */
					if (!IsNameObjPresent(subject, obj_jurisdictionCountryName))
					{
						SetError(ERR_EV_WITHOUT_JURISDICTION_COUNTRY);
					}
					/* 9.2.6 */
					if (!IsNameObjPresent(subject, obj_serialNumber))
					{
						SetError(ERR_EV_WITHOUT_NUMBER);
					}
					/* 9.2.7 */
					if (!IsNameObjPresent(subject, obj_localityName))
					{
						SetError(ERR_EV_WITHOUT_LOCALITY);
					}
					if (!IsNameObjPresent(subject, obj_countryName))
					{
						SetError(ERR_EV_WITHOUT_COUNTRY);
					}
				}
			}

			if (info->qualifiers)
			{
				for (int i = 0; i < sk_POLICYQUALINFO_num(info->qualifiers); i++)
				{
					POLICYQUALINFO *qualinfo = sk_POLICYQUALINFO_value(info->qualifiers, i);
					int nid = OBJ_obj2nid(qualinfo->pqualid);
					if (nid == NID_id_qt_unotice)
					{
						if (qualinfo->d.usernotice->exptext)
						{
							ASN1_STRING *s = qualinfo->d.usernotice->exptext;
							CheckDisplayText(s);
							if (s->type == V_ASN1_BMPSTRING || s->type == V_ASN1_VISIBLESTRING)
							{
								SetError(ERR_INVALID_TYPE_USER_NOTICE);
							}
						}
					}
					else if (nid == NID_id_qt_cps)
					{
						CheckValidURL(qualinfo->d.cpsuri->data, qualinfo->d.cpsuri->length);
					}
					else
					{
						SetError(ERR_INVALID_POLICY_QUALIFIER_ID);
					}
				}
			}
		}
		CERTIFICATEPOLICIES_free(policy);
	}
	while (1);

	if (!bPolicyFound && type == SubscriberCertificate)
	{
		/* Required by CAB 9.3.4 */
		SetError(ERR_NO_POLICY);
	}

	if (type == SubscriberCertificate && !DomainValidated && !OrganizationValidated
		&& !IndividualValidated && !EVValidated)
	{
		SetInfo(INF_UNKNOWN_VALIDATION);
	}
}

static void CheckSAN(X509 *x509, CertType type)
{
	int idx = -1;
	bool bSanFound = false;

	do
	{
		int critical = -1;

		GENERAL_NAMES *names = X509_get_ext_d2i(x509, NID_subject_alt_name, &critical, &idx);

		if (names == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				bSanFound = true;
				continue;
			}
			/* Not found */
			break;
		}
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		bSanFound = true;
	}
	while (1);

	if (!bSanFound)
	{
		/* Required by CAB base 7.1.4.2.1 */
		/* It's not clear if this should also apply to CAs, the CAB base
		 * document doesn't exclude them, but I think it shouldn't apply to CAs. */
		if (type == SubscriberCertificate)
		{
			SetError(ERR_NO_SUBJECT_ALT_NAME);
		}
	}
}

static void CheckCRL(X509 *x509)
{
	int idx = -1;

	do
	{
		int critical = -1;

		STACK_OF(DIST_POINT) *crls = X509_get_ext_d2i(x509, NID_crl_distribution_points, &critical, &idx);

		if (crls == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				continue;
			}
			/* Not found */
			break;
		}

		for (int i = 0; i < sk_DIST_POINT_num(crls); i++)
		{
			DIST_POINT *dp = sk_DIST_POINT_value(crls, i);
			if (dp->distpoint == NULL && dp->CRLissuer == NULL)
			{
				SetError(ERR_INVALID_CRL_DIST_POINT);
			}
			if (dp->distpoint != NULL && dp->distpoint->type == 0)
			{
				/* full name */
				for (int j = 0; j < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); j++)
				{
					GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, j);
					int type;
					ASN1_STRING *uri = GENERAL_NAME_get0_value(gen, &type);
					if (type == GEN_URI)
					{
						CheckValidURL(ASN1_STRING_data(uri), ASN1_STRING_length(uri));
					}
					else
					{
						SetInfo(INF_CRL_NOT_URL);
					}
				}
			}
			else
			{
				/* relative name */
				SetWarning(WARN_CRL_RELATIVE);
			}
		}
		sk_DIST_POINT_pop_free(crls, DIST_POINT_free);
	}
	while (1);
}

static void CheckTime(X509 *x509, struct tm *tm_before, struct tm *tm_after, CertType type)
{
	ASN1_TIME *before = X509_get_notBefore(x509);
	ASN1_TIME *after = X509_get_notAfter(x509);
	bool error = false;

	if (!asn1_time_to_tm(before, tm_before))
	{
		error = true;
	}
	if (!asn1_time_to_tm(after, tm_after))
	{
		error = true;
	}

	if (error)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
		return;
	}

	if (type == SubscriberCertificate)
	{
		/* CAB 9.4.1 */
		if (IsValidLongerThan(*tm_before, *tm_after, 60))
		{
			SetError(ERR_LONGER_60_MONTHS);
		}
		else if (IsValidLongerThan(*tm_before, *tm_after, 39))
		{
			SetWarning(WARN_LONGER_39_MONTHS);
		}
	}
}

static int obj_cmp(const ASN1_OBJECT * const *a, const ASN1_OBJECT * const *b)
{
	return OBJ_cmp(*a, *b);
}

static void CheckDuplicateExtentions(X509 *x509)
{
	STACK_OF(ASN1_OBJECT) *stack = sk_ASN1_OBJECT_new(obj_cmp);

	for (int i = 0; i < X509_get_ext_count(x509); i++)
	{
		X509_EXTENSION *ext = X509_get_ext(x509, i);
		if (ext == NULL)
		{
			SetError(ERR_INVALID);
			continue;
		}
		if (sk_ASN1_OBJECT_find(stack, ext->object) >= 0)
		{
			SetError(ERR_DUPLICATE_EXTENTION);
		}
		else
		{
			sk_ASN1_OBJECT_push(stack, ext->object);
		}
	}
	sk_ASN1_OBJECT_free(stack);
}

void check(unsigned char *cert_buffer, size_t cert_len, CertFormat format, CertType type)
{
	X509_NAME *issuer;
	X509_NAME *subject;
	int ret;
	X509 *x509;
	int ca;
	struct tm tm_before;
	struct tm tm_after;

	Clear();

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

	ret = X509_get_version(x509);
	if (ret != 2)
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

	CheckDuplicateExtentions(x509);

	/* Prohibited in CAB base 7.1.4.2.2c */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& IsNameObjPresent(subject, obj_StreetAddress))
	{
		SetError(ERR_SUBJECT_ADDR);
	}

	/* Required in CAB base 7.1.4.2.2d and 7.1.4.2.2e */
	if (IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_stateOrProvinceName)
		&& !IsNameObjPresent(subject, obj_localityName))
	{
		SetError(ERR_SUBJECT_ORG_NO_PLACE);
	}

	/* Prohibited in CAB base 7.1.4.2.2d or 7.1.4.2.2e */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& (IsNameObjPresent(subject, obj_localityName)
			|| IsNameObjPresent(subject, obj_stateOrProvinceName)))
	{
		SetError(ERR_SUBJECT_NO_ORG_PLACE);
	}

	/* Required by CAB base 7.1.4.2.2g */
	if (IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_countryName))
	{
		SetError(ERR_SUBJECT_COUNTRY);
	}

	CheckPolicy(x509, type, subject);
	CheckSAN(x509, type);

	/* Deprecated in CAB base 7.1.4.2.2a */
	if (IsNameObjPresent(subject, obj_commonName))
	{
		if (type == SubscriberCertificate)
		{
			SetInfo(INF_SUBJECT_CN);
		}
	}

	CheckCRL(x509);
	CheckTime(x509, &tm_before, &tm_after, type);

	X509_free(x509);
}

void check_init()
{
	OpenSSL_add_all_algorithms();

	iconv_utf8 = iconv_open("utf-8", "utf-8");
	iconv_ucs2 = iconv_open("utf-8", "ucs-2be");
	iconv_t61 = iconv_open("utf-8", "CSISO103T618BIT");
	iconv_ucs4 = iconv_open("UCS-4", "utf-8");

	obj_organizationName = OBJ_nid2obj(NID_organizationName);
	obj_localityName = OBJ_nid2obj(NID_localityName);
	obj_stateOrProvinceName = OBJ_nid2obj(NID_stateOrProvinceName);
	obj_countryName = OBJ_nid2obj(NID_countryName);
	obj_commonName = OBJ_nid2obj(NID_commonName);
	obj_givenName = OBJ_nid2obj(NID_givenName);
	obj_surname = OBJ_nid2obj(NID_surname);
	obj_businessCategory = OBJ_nid2obj(NID_businessCategory);
	obj_serialNumber = OBJ_nid2obj(NID_serialNumber);

#if OPENSSL_VERSION_NUMBER < 0x1000200FL
	obj_jurisdictionCountryName = OBJ_txt2obj(OIDjurisdictionCountryName, 1);
#else
	obj_jurisdictionCountryName = OBJ_nid2obj(NID_jurisdictionCountryName);
#endif

	obj_StreetAddress = OBJ_txt2obj(OIDStreetAddress, 1);
	obj_postalCode = OBJ_txt2obj(OIDpostalCode, 1);
}

void check_finish()
{
	iconv_close(iconv_utf8);
	iconv_close(iconv_ucs2);
	iconv_close(iconv_t61);
	iconv_close(iconv_ucs4);
#if OPENSSL_VERSION_NUMBER < 0x1000200FL
	ASN1_OBJECT_free(obj_jurisdictionCountryName);
#endif
	ASN1_OBJECT_free(obj_StreetAddress);
	ASN1_OBJECT_free(obj_postalCode);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

