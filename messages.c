#include <stdlib.h>
#include <string.h>
#include "checks.h"

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

	if (GetBit(errors, ERR_INVALID))
	{
		strcat(buffer, "E: Error parsing certificate\n");
	}
	if (GetBit(errors, ERR_ISSUER_ORG_NAME))
	{
		strcat(buffer, "E: Issuer without organization name\n");
	}
	if (GetBit(errors, ERR_ISSUER_COUNTRY))
	{
		strcat(buffer, "E: Issuer without country name\n");
	}
	if (GetBit(errors, ERR_SUBJECT_ADDR))
	{
		strcat(buffer, "E: Subject without OrganizationName but with StreetAddress\n");
	}
	if (GetBit(errors, ERR_SUBJECT_ORG_NO_PLACE))
	{
		strcat(buffer, "E: Subject with OrganizationName but without StateOrProvince or LocalityName\n");
	}
	if (GetBit(errors, ERR_SUBJECT_NO_ORG_PLACE))
	{
		strcat(buffer, "E: Subject without OrganizationName but with StateOrProvince or LocalityName\n");
	}
	if (GetBit(errors, ERR_INVALID_ENCODING))
	{
		strcat(buffer, "E: Fails decoding the characterset\n");
	}
	if (GetBit(errors, ERR_STRING_WITH_NUL))
	{
		strcat(buffer, "E: Contains a null character in the distinguished name\n");
	}
	if (GetBit(errors, ERR_INVALID_TAG_TYPE))
	{
		strcat(buffer, "E: Distinguished name contains invalid DirectoryString type\n");
	}
	if (GetBit(errors, ERR_NON_PRINTABLE))
	{
		strcat(buffer, "E: The distinguished name contains non-printable control characters\n");
	}
	if (GetBit(errors, ERR_SUBJECT_COUNTRY))
	{
		strcat(buffer, "E: Subject with OrganizationName but without country name\n");
	}
	if (GetBit(errors, ERR_DOMAIN_WITH_ORG_OR_ADDRESS))
	{
		strcat(buffer, "E: Domain validated certificate but with organization name or address\n");
	}
	if (GetBit(errors, ERR_IDENTITY_WITHOUT_ORG_OR_ADDRESS))
	{
		strcat(buffer, "E: Identity validated certificate but without organization name or address\n");
	}
	if (GetBit(errors, ERR_NO_POLICY))
	{
		strcat(buffer, "E: No policy extension\n");
	}
	if (GetBit(errors, ERR_NO_SUBJECT_ALT_NAME))
	{
		strcat(buffer, "E: No Subject alternative name extension\n");
	}
	if (GetBit(errors, ERR_NOT_VERSION3))
	{
		strcat(buffer, "E: Certificate not version 3\n");
	}
	if (GetBit(errors, ERR_INVALID_URL))
	{
		strcat(buffer, "E: Error parsing URL\n");
	}

	if (GetBit(warnings, WARN_NON_PRINTABLE_STRING))
	{
		strcat(buffer, "W: The distinguage name contains something that is not a PrintableString or UTF8String\n");
	}

	if (GetBit(info, INF_SUBJECT_CN))
	{
		strcat(buffer, "I: Subject has a deprecated CommonName\n");
	}
	if (GetBit(info, INF_CRL_NOT_URL))
	{
		strcat(buffer, "I: CRL is not a URL\n");
	}

	return buffer;
}

