#include <stdlib.h>
#include <stdio.h>
#include <gnutls/x509.h>
#include "checks.h"
#include "messages.h"

static int LoadCert(const char *filename, gnutls_x509_crt_t *cert)
{
        unsigned char *buffer;
        long size;
        FILE *f;
        gnutls_datum_t pem;

        f = fopen(filename, "rb");
        if (f == NULL)
        {
                return -1;
        }
        if (fseek(f, 0, SEEK_END) != 0)
        {
                return -1;
        }
        size = ftell(f);
        if (size == -1)
        {
                return -1;
        }
        buffer = malloc(size);
        if (fseek(f, 0, SEEK_SET) != 0)
        {
                free(buffer);
                return -1;
        }
        if (fread(buffer, 1, size, f) != size)
        {
                free(buffer);
                return -1;
        }
        fclose(f);

        if (gnutls_x509_crt_init(cert) != 0)
        {
                free(buffer);
                return -1;
        }

        pem.data = buffer;
        pem.size = size;

        if (gnutls_x509_crt_import(*cert, &pem, GNUTLS_X509_FMT_PEM) != 0)
        {
                free(buffer);
                return -1;
        }
        free(buffer);

        return 0;
}


int main(int argc, char *argv[])
{
	gnutls_x509_crt_t cert;

        if (argc != 2)
        {
                printf("Usage: x509lint file\n");
                exit(1);
        }

	if (LoadCert(argv[1], &cert) != 0)
	{
		fprintf(stderr, "Unable to read certificate\n");
		exit(1);
	}

	check_init();
	
	check(cert, SubscriberCertificate);

	char *m = get_messages();
	printf("%s", m);
	free(m);

        gnutls_x509_crt_deinit(cert);

	check_finish();

	return 0;
}

