#ifndef _CHECKS_H_
#define _CHECKS_H_

typedef enum { SubscriberCertificate, IntermediateCA, RootCA } CertType;
typedef enum { PEM, DER } CertFormat;

/* This should never happen in certificates, and violates a MUST */
#define ERR_INVALID                            0
#define ERR_ISSUER_ORG_NAME                    1
#define ERR_ISSUER_COUNTRY                     2
#define ERR_SUBJECT_ADDR                       3
#define ERR_SUBJECT_ORG_NO_PLACE               4
#define ERR_SUBJECT_NO_ORG_PLACE               5
#define ERR_INVALID_ENCODING                   6
#define ERR_STRING_WITH_NUL                    7
#define ERR_INVALID_TAG_TYPE                   8
#define ERR_NON_PRINTABLE                      9
#define ERR_SUBJECT_COUNTRY                   10
#define ERR_DOMAIN_WITH_ORG_OR_ADDRESS        11
#define ERR_IDENTITY_WITHOUT_ORG_OR_ADDRESS   12
#define ERR_NO_POLICY                         13
#define ERR_NO_SUBJECT_ALT_NAME               14
#define ERR_NOT_VERSION3                      15
#define ERR_INVALID_URL                       16
#define ERR_LONGER_60_MONTHS                  17
#define ERR_DATE_OUT_OF_RANGE                 18
#define ERR_ANY_POLICY_WITH_OTHER             19

/* This violates a SHOULD (or MUST with exception that can't be checked) */
#define WARN_NON_PRINTABLE_STRING      0
#define WARN_IA5                       1
#define WARN_LONGER_39_MONTHS          2

/* Certificate is valid, but contains things like deprecated or not checked. */
#define INF_SUBJECT_CN                 0
#define INF_STRING_NOT_CHECKED         1	/* Software doesn't know how to check it yet. */
#define INF_CRL_NOT_URL                2

extern unsigned int errors[1];
extern unsigned int warnings[1];
extern unsigned int info[1];

void check_init();
void check(const unsigned char *cert_buffer, size_t cert_len, CertFormat format, CertType type);
int GetBit(unsigned int *val, int bit);
void check_finish();


#endif

