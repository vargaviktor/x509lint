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
	"E: Error parsing certificate (ASN.1)\n", /* ERR_INVALID*/
	"E: Issuer without organizationName (CAB 1.7.3 7.1.4.3.1)\n", /* ERR_ISSUER_ORG_NAME*/ 
	"E: Issuer without countryName (CAB 1.7.3 7.1.4.3.1)\n", /* ERR_ISSUER_COUNTRY */
	"E: Subject without organizationName, givenName or surname but with streetAddress (CAB 1.7.3 7.1.4.2.2d)\n", /* ERR_SUBJECT_ADDR */
	"E: Subject with organizationName, givenName or surname but without stateOrProvince or localityName (CAB 1.7.3 7.1.4.2.2ef)\n", /* ERR_SUBJECT_ORG_NO_PLACE */
	"E: Subject without organizationName, givenName or surname but with stateOrProvince or localityName (CAB 1.7.3 7.1.4.2.2ef)\n", /* ERR_SUBJECT_NO_ORG_PLACE */
	"E: Fails decoding the characterset (ASN.1)\n", /*ERR_INVALID_ENCODING */
	"E: Contains a null character in the string (ASN.1)\n", /* ERR_STRING_WITH_NUL */
	"E: Name entry contains an invalid type (RFC 5280 A.2.)\n", /* ERR_INVALID_NAME_ENTRY_TYPE */
	"E: The string contains non-printable control characters (ASN.1)\n", /* ERR_NON_PRINTABLE */
	"E: Subject with organizationName, givenName or surname but without countryName (CAB 1.7.3 7.1.4.2.2h)\n", /* ERR_SUBJECT_COUNTRY */
	"E: Domain validated certificate with organizationName (CAB 1.7.3 3.2.2.2, 7.1.4.2.2b, 7.1.6.4)\n", /* ERR_DOMAIN_WITH_ORG */
	"E: Organization validated certificate but without organizationName (CAB 1.7.3 3.2.2.2,  7.1.4.2.2b, 7.1.6.4)\n", /* ERR_ORGANIZATION_WITHOUT_ORG */
	"E: No policy extension (CAB 1.7.3 7.1.2.3)\n", /* ERR_NO_POLICY */
	"E: No Subject alternative name extension (CAB 1.7.3 7.1.4.2.1)\n", /* ERR_NO_SUBJECT_ALT_NAME */
	"E: Certificate not version 3 (MSRP A1)\n", /* ERR_NOT_VERSION3 */
	"E: Error parsing URL/Invalid URL (RFC 3986)\n", /* ERR_INVALID_URL */
	"E: The certificate is valid for longer than 12 months (CAB 1.7.3 9.4.1)\n", /* ERR_LONGER_12_MONTHS */
	"E: countryName not 2 characters long (RFC 5280 A.1; CAB 1.7.3 7.1.4.2.2h)\n", /* ERR_COUNTRY_SIZE */
	"E: Invalid time format (ASN.1)\n", /* ERR_INVALID_TIME_FORMAT */
	"E: Duplicate extension (RFC 5280 4.2)\n", /* ERR_DUPLICATE_EXTENSION */
	"E: CRL DistributionPoint without distributionPoint or cRLIssuer (RFC 5280 4.2.1.13.)\n", /* ERR_CRL_DIST_POINT_WITHOUT_DISTPOINT_OR_ISSUER */
	"E: Invalid display text type (RFC 5280 A.1.)\n", /* ERR_INVALID_DISPLAY_TEXT_TYPE */
	"E: Invalid display text length (RFC 5280 A.1.)\n", /* ERR_INVALID_DISPLAY_TEXT_LENGTH */
	"E: Invalid user notice type (RFC 5280 4.2.1.4; RFC 6818)\n", /* ERR_INVALID_TYPE_USER_NOTICE */
	"E: Invalid policy qualifier id (RFC 5280 A.1.)\n", /* ERR_INVALID_POLICY_QUALIFIER_ID */
	"E: Individual without name (CAB 1.7.3 7.1.6.4)\n", /* ERR_INDIVIDUAL_WITHOUT_NAME */
	"E: Individual without country (CAB 1.7.3 7.1.6.4)\n", /* ERR_INDIVIDUAL_WITHOUT_COUNTRY */
	"E: EV certificate without organization (EVGL 9.2.1)\n", /* ERR_EV_WITHOUT_ORGANIZATION */
	"E: EV certificate without business (EVGL 9.2.4)\n", /* ERR_EV_WITHOUT_BUSINESS */
	"E: EV certificate without jurisdiction country (EVGL 9.2.5)\n", /* ERR_EV_WITHOUT_JURISDICTION_COUNTRY */
	"E: EV certificate without Subject serial number (EVGL 9.2.6)\n", /* ERR_EV_WITHOUT_NUMBER */
	"E: Domain validated certificate but with streetAddress (CAB 1.7.3 7.1.6.4)\n", /* ERR_DOMAIN_WITH_STREET */
	"E: Domain validated certificate but with localityName (CAB 1.7.3 7.1.6.4)\n", /* ERR_DOMAIN_WITH_LOCALITY */
	"E: Domain validated certificate but with stateOrProvinceName (CAB 1.7.3 7.1.6.4)\n", /* ERR_DOMAIN_WITH_STATE */
	"E: Domain validated certificate but with postalCode (CAB 1.7.3 7.1.6.4)\n", /* ERR_DOMAIN_WITH_POSTAL */
	"E: Organization validated certificate but without country (CAB 1.7.3 7.1.6.4)\n", /* ERR_ORGANIZATION_WITHOUT_COUNTRY */
	"E: commonName too long (RFC 5280 A.1.)\n", /* ERR_COMMON_NAME_SIZE */
	"E: localityName too long (RFC 5280  A.1.)\n", /* ERR_LOCALITY_NAME_SIZE */
	"E: stateOrProvinceName too long (RFC 5280  A.1.)\n", /* ERR_STATE_NAME_SIZE */
	"E: organizationName too long (RFC 5280  A.1.)\n", /* ERR_ORGANIZATION_NAME_SIZE */
	"E: organizationalUnitName too long (RFC 5280 A.1.)\n", /* ERR_ORGANIZATIONAL_UNIT_NAME_SIZE */
	"E: serialNumber too long (RFC 5280 A.1.)\n", /* ERR_SERIAL_NUMBER_SIZE */
	"E: postalCode too long (RFC 5280 A.1.)\n", /* ERR_POSTAL_CODE_SIZE */
	"E: emailAddress too long (RFC 5280 A.1.)\n", /* ERR_EMAIL_SIZE */
	"E: givenName too long (RFC 5280 A.1.)\n", /* ERR_GIVEN_NAME_SIZE */
	"E: surname too long (RFC 5280 A.1.)\n", /* ERR_SURNAME_SIZE */
	"E: streetAddress too long (RFC 5280 A.1.)\n", /* ERR_STREET_ADDRESS_SIZE */
	"E: authorityInformationAccess is marked critical (RFC 5280 4.2.2.1.)\n", /* ERR_AIA_CRITICAL */
	"E: No OCSP over HTTP (RFC 5280 4.2.2.1.)\n",  /* ERR_NO_OCSP_HTTP */
	"E: no authorityInformationAccess extension (RFC 5280 4.2.2.1.)\n", /* ERR_NO_AIA */
	"E: Invalid type in SAN entry (RFC 5280 4.2.1.6.)\n", /* ERR_SAN_TYPE */
	"E: Invalid type in GeneralName (RFC 5280 A.2.)\n", /* ERR_GEN_NAME_TYPE */
	"E: EV certificate valid longer than 12 months (EVGL 9.4)\n", /* ERR_EV_LONGER_12_MONTHS */
	"E: subjectAltName without name (RFC 5280 4.2.1.6.)\n", /* ERR_SAN_WITHOUT_NAME */
	"E: Invalid length of IP address (RFC 5280 A.2)\n", /* ERR_IP_FAMILY */
	"E: commonName not in subjectAltName extension (CAB 1.7.3 7.1.4.2.2)\n", /* ERR_CN_NOT_IN_SAN */
	"E: Invalid length of businessCategory\n (EVGL x)", /* ERR_BUSINESS_CATEGORY_SIZE */
	"E: Invalid length of dnQualifier (title) (RFC 5280 A.1.)\n", /* ERR_DN_QUALIFIER_SIZE */
	"E: URL contains a null character (RFC 3986)\n", /* ERR_URL_WITH_NUL */
	"E: postOfficeBox too long (RFC 5280 A.1.)\n", /* ERR_POST_OFFICE_BOX_SIZE */
	"E: IP address in dns name (RFC 5280 4.2.1.6.)\n", /* ERR_IP_IN_DNSNAME */
	"E: Serial number not positive (MRP 2.7 5.2; ASN.1 4.1 ?x)\n", /* ERR_SERIAL_NOT_POSITIVE */
	"E: Serial number too large (ASN.1 4.1)\n", /* ERR_SERIAL_TOO_LARGE */
	"E: ASN1 integer not minimally encoded (ASN.1 4.1)\n", /* ERR_ASN1_INTEGER_NOT_MINIMAL */
	"E: RSA modulus smaller than 2048 bit (CAB 1.7.3 6.1.5; MSRP A4)\n", /* ERR_RSA_SIZE_2048 */ 
	"E: RSA public exponent not odd (CAB 1.7.3 6.1.6) \n", /* ERR_RSA_EXP_NOT_ODD */
	"E: RSA public exponent not equal to 3 or more (CAB 1.7.3 6.1.6)\n", /* ERR_RSA_EXP_3 */
	"E: RSA modulus has small factor (CAB 1.7.3 6.1.6; NIST SP 800-89 5.3.3)\n", /* ERR_RSA_SMALL_FACTOR */ /* commented out not working in some cases !!!!*/
	"E: EC point at infinity (ec)\n", /* ERR_EC_AT_INFINITY */
	"E: EC point not on curve (ec)\n", /* ERR_EC_POINT_NOT_ON_CURVE */
	"E: EC key has invalid group order (ec)\n", /* ERR_EC_INVALID_GROUP_ORDER */
	"E: EC key has incorrect group order (ec)\n", /* ERR_EC_INCORRECT_ORDER */
	"E: EC curve is not one of the allowed curves (ec)\n", /* ERR_EC_NON_ALLOWED_CURVE */
	"E: Unknown public key type (CAB 1.7.3 6.1.5)\n", /* ERR_UNKNOWN_PUBLIC_KEY_TYPE */
	"E: Subject without organizationName, givenName or surname but with postalCode (CAB 1.7.37.1.4.2.2g)\n", /* ERR_SUBJECT_POSTAL */
	"E: Domain validated certificate but with givenName or surname (CAB 1.7.3 7.1.6.4)\n", /* ERR_DOMAIN_WITH_NAME */
	"E: Subject with givenName or surname but without the CAB 1.7.3 IV policy oid (CAB 1.7.3 7.1.4.2.2c)\n", /* ERR_NAME_NO_IV_POLICY */
	"E: CA root certificate with Extended Key Usage (CAB 1.7.3 7.1.2.1d) \n", /* ERR_ROOT_CA_WITH_EKU */
	"E: Extended Key Usage without any entries (RFC 5280 4.2.1.12.)\n", /* ERR_EMPTY_EKU */
	"E: Extended Key Usage lacks a required purpose (RCF 5280 4.2.1.12.) (IntelAMTvProEKU)\n", /* ERR_MISSING_EKU */ 
	"E: Invalid length of domainComponent (RFC 5280 A.1.)\n", /* ERR_DOMAINCOMPONENT_SIZE */
	"E: Invalid length of unstructuredName (RFC 5280 A.1.)\n", /* ERR_UNSTRUCTUREDNAME_SIZE */
	"E: Teletex string with an escape sequence (ASN.1)\n", /* ERR_TELETEX_WITH_ESCAPE */
	"E: Baseline Requirements policy present for non server authentication certificate (CAB 1.7.3 x)\n", /* ERR_POLICY_BR */
	"E: RSA modulus is negative (CAB 1.7.3 6.1.5)\n", /* ERR_RSA_MODULUS_NEGATIVE */
	"E: No key usage (RFC 5280 4.2.1.3.)\n", /* ERR_NO_KEY_USAGE */
	"E: Key usage is empty (RFC 5280 4.2.1.3.)\n", /* ERR_KEY_USAGE_EMPTY */
	"E: Key usage is too long (RFC 5280 4.2.1.3.)\n", /* ERR_KEY_USAGE_TOO_LONG */
	"E: Enduser certificate Key usage has keyCertSign or CRLSign (CAB 1.7.3 7.1.2.3e)\n", /* ERR_KEY_USAGE_HAS_CERT_SIGN_OR_CRL_SIGN */
	"E: AKID missing (RFC 5280 4.2.1.1)\n", /* ERR_AKID_MISSING */
	"E: No CRL distpoint with all reasons (RFC 5280 4.2.1.13.)\n", /* ERR_NOT_ALL_CRL_REASONS */
	"E: CRL DistributionPoint's cRLIssuer empty (RFC 5280 4.2.1.13.)\n", /* ERR_CRL_ISSUER_EMPTY */
	"E: CRL DistributionPoint's cRLIssuer not a directoryName (RFC 5280 4.2.1.13.)\n", /* ERR_CRL_ISSUER_NOT_DIRNAME */
	"E: CRL DistributionPoint's distributionPoint empty (RFC 5280 4.2.1.13.)\n", /* ERR_CRL_DISTPOINT_EMPTY */
	"E: CRL DistributionPoint's cRLIssuer is relative, but has more than 1 entry (RFC 5280 4.2.1.13.)\n", /* ERR_RELATIVE_CRL_ISSUER_COUNT */
	"E: Invalid CRL reason (RFC 5280 4.2.1.13.)\n", /* ERR_INVALID_CRL_REASON */
	"E: CA certificate without Basic Constraints (MSRP A3)\n", /* ERR_NO_BASIC_CONSTRAINTS */
	"E: CA certificate with non-critical Basic Constraints (CAB 1.7.3 7.2.1)\n", /* ERR_BASIC_CONSTRAINTS_NOT_CRITICAL */
	"E: CA certificate with CA:false (CAB 1.7.3 7.2.1)\n", /* ERR_CA_CERT_NOT_CA */
	"E: Basic Constraints with negative length (RFC 5280 4.2.1.9.)\n", /* ERR_BASIC_CONSTRAINTS_NEG_PATHLEN */
	"E: Basic Constraints with pathlen for non-CA (RFC 5280 4.2.1.9.) (MSRP A11)\n", /* ERR_BASIC_CONSTRAINTS_NO_CA_PATHLEN */
	"E: Empty issuer (RFC 5280 4.2.1.4.)\n", /* ERR_EMPTY_ISSUER */
	"E: Empty subject (RFC 5280 4.1.2.6.)\n", /* ERR_EMPTY_SUBJECT */
	"E: SAN is not critical (RFC 5280 4.1.2.6.)\n", /* ERR_SAN_NOT_CRITICAL */
	"E: Key usage not critical (CAB 1.7.3 7.1.2)\n", /* ERR_KEY_USAGE_NOT_CRITICAL */
	"E: Empty SAN (CAB 1.7.3 7.1.4.2.1)\n", /* ERR_SAN_EMPTY */
	"E: Signature algorithm mismatch (RFC 5280 5.1.1.2)\n", /* ERR_SIG_ALG_MISMATCH */
	"E: AKID is critical (CAB 1.7.3 7.1.2.3)\n", /* ERR_AKID_CRITICAL */
	"E: SKID missing (CAB 1.7.3 7.1.2.3)\n", /* ERR_SKID_MISSING */
	"E: SKID critical (CAB 1.7.3 7.1.2.3)\n", /* ERR_SKID_CRITICAL */
    "E: Algorithm parameter missing (RFC 5280 5.1.1.2)\n", /* ERR_ALG_PARAMETER_MISSING */
	"E: Bit string with leading 0 (ASN.1)\n", /* ERR_BIT_STRING_LEADING_0 */
	"E: Algorithm parameter not NULL, where it shall (RFC 5280 5.1.1.2)\n", /* ERR_ALG_PARAMETER_NOT_NULL */
	"E: Unknown signature algorithm (RFC 5280 5.1.1.2)\n", /* ERR_UNKNOWN_SIGNATURE_ALGORITHM */
	"E: Algorithm parameter present, where shall not (RFC 5280 5.1.1.2)\n", /* ERR_ALG_PARAMETER_PRESENT */
    
    
	"E: Not using a named curve (ec)\n", /* ERR_NOT_NAMED_CURVE */
	"E: Key usage with unknown bit (RFC5280 4.2.1.3.)\n", /* ERR_KEY_USAGE_UNKNOWN_BIT */
	"E: Basic Constraints with pathlen but key usage without cert sign (RFC 5280 4.2.1.9.)\n", /* ERR_BASIC_CONSTRAINTS_NO_CERT_SIGN_PATHLEN */
	"E: AKID without a key identifier (RFC 5280 4.2.1.1)\n", /* ERR_AKID_WITHOUT_KEY_ID */
	"E: Invalid general name type (RFC 5280 A.2.)\n", /* ERR_INVALID_GENERAL_NAME_TYPE */
	"E: EC key without parameters (ec)\n", /* ERR_EC_NO_PARAMETER */
    
    "E: Algorithm with wrong ASN.1 type\n", /* ERR_ALG_WRONG_TYPE */
	"E: Algorithm parameters failed to decode\n", /* ERR_ALG_FAILED_DECODING */
	"E: Default value written instead of ommited\n", /* ERR_DEFAULT_VALUE */
	"E: Hash algorithm not allowed\n", /* ERR_NOT_ALLOWED_HASH */
	"E: Mask algorithm not allowed\n", /* ERR_NOT_ALLOWED_MASK_ALGORITHM */
	"E: PSS hash algorithm not equal\n", /* ERR_PSS_HASH_NOT_EQUAL */
	"E: Invalid PSS salt length\n", /* ERR_PSS_INVALID_SALT_LENGTH */
	"E: Invalid PSS trailer\n", /* ERR_PSS_INVALID_TRAILER */
   	"E: Issuer without commonName (CAB 1.7.3 7.1.4.3.1)\n", /* ERR_ISSUER_COMMONNAME*/
	"E: RSA modulus divisable with other than 8 (CAB 1.7.3 6.1.5)\n", /* ERR_RSA_SIZE_DIVNON8 */
	"E: Certificate longer than 398 days (CAB 1.7.3 6.1.5)\n", /* ERR_LONGER_398DAYS */ /* Not implemennted yet !!!*/ 
	"E: FOR CAB ICA: ONLY AFTER 2020-08-20!!! Subscriber or intermediate certificate without Extended Key Usage(MRP 2.7 5.3; CAB 1.7.3 7.1.2.2,7.1.2.3; MSRP 4.A.18.) \n", /* ERR_NO_EKU */ /* possible false for cross certificates) */
	"E: AnyEKU is not enabled in intermediate/root (MRP 2.7 5.3)\n", /* ERROR_ANY_EKU_MOZILLA */
	"E: Invalid EKU combo in certificate (2MRP 2.7 5.3)\n", /* ERROR_INVALID_EKU_COMBO_IN_MOZILLA */
	"E: EV/OV cert without orgID (CAB 1.7.3 x; EVGL x)\n", /* ERR_EVOV_WITHOUT_ORGID */
	"E: NO DATE AND COMBO CHECKED!!! EV cert without CABForgID (EVGL x)\n", /* ERR_EV_WITHOUT_CAB 1.7.3FORGID	*/
	"E: orgID, CAB 1.7.3ForgID is not in the needed format (EVGL x; ETSI 319412-1)\n", /* ERR_ORGID_FORMAT */ /* needs checid function, not implemented yet. !!!!)*/
	"E: Certificate serial too small, no place for 64 bit random\n", /* ERR_NO64BITRANDOM */
	"E: WRONG TEST!!! OCSP EKU not alone. (MSRP A12)\n", /* ERROR_OCSP_NOT_ALONE */
	"E: Subsciber certificate with Certsign and/or CRLSign (x)", /* ERR_KEY_USAGE_HAS_CERT_SIGN_OR_CRL_SIGN */
};

static const char *warning_strings[] = {
	"W: The name entry contains something that is not a PrintableString or UTF8String (RFC 5280 B.)\n", /* WARN_NON_PRINTABLE_STRING */
	"W: The certificate is valid for longer than 39 months (not used)\n", /* WARN_LONGER_39_MONTHS */
	"W: Called with wrong certificate type, not subscriber, intermediate or root (info)\n", /* WARN_CALLED_WITH_WRONG_TYPE */
	"W: CRL distribution point uses relative name (RFC 5280 4.2.1.13)\n", /* WARN_CRL_RELATIVE */
	"W: No HTTP URL for issuing certificate (RFC 5280 4.2.2.1.)\n", /* WARN_NO_ISSUING_CERT_HTTP */
	"W: Duplicate SAN entry (RFC 5280 4.2.1.6)\n", /* WARN_DUPLICATE_SAN */
	"W: EV certificate valid longer than 12 months (not used)\n", /* WARN_EV_LONGER_12_MONTHS */
	"W: Unknown extended key usage (info)\n", /* WARN_UNKNOWN_EKU */ /* need to add more eku !!!!! */
	"W: RSA public exponent not in range of 2^16+1 to 2^256-1 (CAB 1.7.3 6.1.6)\n", /* WARN_RSA_EXP_RANGE */
	"W: Policy information has qualifier other than CPS URI (CAB 1.7.3 7.1.2.2, 7.1.2.3)\n", /* WARN_POLICY_QUALIFIER_NOT_CPS */
	"W: explicitText is not using a UTF8String (RFC 5280 4.2.1.4; RFC 6818)\n", /* WARN_EXPLICIT_TEXT_ENCODING */
	"W: Subscriber certificate without Extended Key Usage\n (not used)", /* WARN_NO_EKU */ /* added a bug also with this name, because its now a bug */
	"W: No commonName (RFC 5280 A.1.)\n", /* WARN_NO_CN */
	"W: TLS client with DNS or IP address (info)\n", /* WARN_TLS_CLIENT_DNS */
	"W: Key usage not critical (RFC 5280 4.2.1.3)\n", /* WARN_KEY_USAGE_NOT_CRITICAL */ 
	"W: Key usage doesn't have keyCertSign or cRLSign (RFC 5280 4.2.1.3)\n", /* WARN_KEY_USAGE_NO_CERT_OR_CRL_SIGN */
	"W: ETSI advanced SSL OIDs, CAB 1.7.3 needed instead (info)\n", /* WARN_ETSI_ADV_SSL_OIDS */
	
};
/* an error is also there, with Key Usage not critical */


static const char *info_strings[] = {
	"I: Subject has a deprecated CommonName (CAB 1.7.3 7.1.4.2.2a)\n", /* INF_SUBJECT_CN */
	"I: String not checked (info)\n", /* INF_STRING_NOT_CHECKED */
	"I: CRL is not a URL (RFC 5280 4.2.1.13)\n", /* INF_CRL_NOT_URL */
	"I: Unknown validation policy (info)\n", /* INF_UNKNOWN_VALIDATION */
	"I: Name entry length not checked (info)\n", /* INF_NAME_ENTRY_LENGTH_NOT_CHECKED */
	"I: Checking as leaf certificate (info)\n", /* INF_CHECKING_LEAF */
	"I: Checking as intermediate CA certificate (info)\n", /* INF_CHECKING_INTERMEDIATE_CA */
	"I: Checking as root CA certificate (info)\n", /* INF_CHECKING_ROOT_CA */
	"I: Qualfied certificate (info)\n", /* INFO_QUALIFIED */
};

/* 
 * Turn the error information into strings.
 * Returns a buffer that should be free()d
 */
char *get_messages()
{
	char *buffer;

	/* Should be large enough for all strings. */
	buffer = malloc(16384);
	buffer[0] = '\0';

	for (int i = 0; i <= MAX_ERR; i++)
	{
		if (GetBit(errors, i))
		{
			strcat(buffer, error_strings[i]);
		}
	}

	for (int i = 0; i <= MAX_WARN; i++)
	{
		if (GetBit(warnings, i))
		{
			strcat(buffer, warning_strings[i]);
		}
	}

	for (int i = 0; i <= MAX_INF; i++)
	{
		if (GetBit(info, i))
		{
			strcat(buffer, info_strings[i]);
		}
	}

	return buffer;
}