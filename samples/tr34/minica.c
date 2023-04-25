/* A mini Certificate Authority */
/* To compile: xlc -qdll -ominica minica.c /usr/lib/GSKCMS31.x */

#include <stdio.h>
#include <string.h>

#include <gskcms.h>

#ifndef FALSE
#define FALSE			0
#endif
#ifndef TRUE
#define TRUE			-1
#endif

#define TR34_DBFILE		"tr34.kdb"
#define TR34_DBPASSWORD	"tr34pw"
#define TR34_CALABEL	"tr34ca"
#define TR34_CASUBJECT	"CN=Agilify CA,O=Agilify,C=AU"
#define TR34_CAFILE		"tr34cacert.pem"
#define TR34_CRLNUMBER	1
#define TR34_CRLFILE	"crl.pem"

int main(int argc, char **argv)
{
	gsk_status					rc;
	gsk_handle					hdb;
	x509_revoked_certificates	revokes;
	gsk_buffer					cabuffer, crlbuffer, csrbuffer, certbuffer;
	gskdb_database_type			dbtype;
	int							nrecords, i;
	char						*csrfn, *certfn, csr[8192];
	FILE						*f;

	if (argc != 3) {
		fprintf(stderr, "Usage: minica input_csr.pem output_cert.pem\n");
		return 8;
	}
	csrfn = argv[1];
	certfn = argv[2];

	/* create a key database, if necessary */
	rc = gsk_create_database(TR34_DBFILE,				// file name
							 TR34_DBPASSWORD,			// file password
							 gskdb_dbtype_key,			// file type
							 0, 						// record length (0 = use default)
							 0, 						// password expiry (0 = never)
							 &hdb);						// database handle
	fprintf(stderr, "gsk_create_database(%s) rc=%08X\n", TR34_DBFILE, rc);
	/* ignore "already exists" */
	if (rc != 0 && rc != CMSERR_DB_EXISTS) {
		fprintf(stderr, "ERROR: Failed to create key database\n");
		return 12;
	}
	if (rc == CMSERR_DB_EXISTS) {
		rc = gsk_open_database(TR34_DBFILE,
							   TR34_DBPASSWORD,
							   TRUE,
							   &hdb,
							   &dbtype,
							   &nrecords);
		fprintf(stderr, "gsk_open_database(%s) rc=%08X\n", TR34_DBFILE, rc);
		if (rc != 0) {
			fprintf(stderr, "ERROR: Failed to open key database\n");
			return 12;
		}
		else {
			printf("Database contains %d records\n", nrecords);
		}
	}

	/* create a self-signed CA certificate, if not already in db */
	rc = gsk_query_database_label(hdb, TR34_CALABEL);
	if (rc == 0) {
		/* already exists */
	}
	else if (rc == CMSERR_RECORD_NOT_FOUND) {
		fprintf(stderr, "Creating self-signed CA certificate. This could take a while...\n");
		rc = gsk_create_self_signed_certificate(hdb,
												TR34_CALABEL,
												x509_alg_sha512WithRsaEncryption,
												4096,		// bit strength
												TR34_CASUBJECT,
												9999,		// days valid
												TRUE,		// TRUE = CA certificate
												NULL);		// no extensions
		fprintf(stderr, "gsk_create_self_signed_certificate rc=%08X\n", rc);
		/* ignore "already exists" */
		if (rc != 0 && rc != CMSERR_LABEL_NOT_UNIQUE) {
			fprintf(stderr, "ERROR: Failed to create self-signed certificate\n");
			return 12;
		}
	}
	else {
		fprintf(stderr, "gsk_query_database_lebel rc=%08X\n", rc);
	}

	/* write CA certificate out as a PEM file */
	rc = gsk_export_certificate(hdb,
								TR34_CALABEL,
								gskdb_export_pkcs7_base64,
								&cabuffer);
	fprintf(stderr, "gsk_export_certificate(TR-34 CA) rc=%08X\n", rc);
	if (rc != 0) {
		fprintf(stderr, "ERROR: Failed to export CA certificate\n");
		return 12;
	}
	f = fopen(TR34_CAFILE, "wb");
	if (f == NULL){
		perror("Error opening CA PEM file for write access");
		return 12;
	}
	fwrite(cabuffer.data, 1, cabuffer.length, f);
	fclose(f);
	printf("\nCA certificate written to file, %s\n\n", TR34_CAFILE);
	gsk_free_buffer(&cabuffer);

	/* create a CRL, signed by the CA */
	revokes.count = 0;
	rc = gsk_create_signed_crl(hdb,
							   TR34_CALABEL,
							   TR34_CRLNUMBER,
							   9999,
							   &revokes,
							   NULL,
							   &crlbuffer);
	fprintf(stderr, "gsk_create_signed_crl rc=%08X\n", rc);
	/* ignore "already exists" */
	if (rc != 0 && rc != CMSERR_LABEL_NOT_UNIQUE) {
		fprintf(stderr, "ERROR: Failed to create self-signed CRL\n");
		return 12;
	}

	/* write signed CRL to a PEM file */
	f = fopen(TR34_CRLFILE, "wb");
	if (f == NULL) {
		perror("Error opening CRL file for write access");
	}
	else {
		rc = fwrite(crlbuffer.data, 1, crlbuffer.length, f);
		if (rc == crlbuffer.length) {
			printf("\nCRL written to file, %s\n", TR34_CRLFILE);
		}
		else {
			perror("Error writing CRL to file");
		}
		fclose(f);
	}
	printf(" \n");
	gsk_free_buffer(&crlbuffer);

	/* read certificate signing request */
	f = fopen(csrfn, "rb");
	if (f == NULL) {
		perror("Error opening certificate signing request file");
		return 12;
	}
	rc = fread(csr, 1, sizeof(csr), f);
	fclose(f);
	csrbuffer.length = rc;
	csrbuffer.data = csr;
	rc = gsk_create_signed_certificate_record(hdb,
											  TR34_CALABEL,
											  9998,
											  FALSE,
											  x509_alg_sha256WithRsaEncryption,
											  NULL,
											  &csrbuffer,
											  &certbuffer);
	fprintf(stderr, "gsk_create_signed_certificate_record rc=%08X\n", rc);
	if (rc != 0) {
		fprintf(stderr, "ERROR: Failed to create signed certificate\n");
		return 12;
	}

	/* write signed certificate */
	printf(" \n");
	f = fopen(certfn, "wb");
	if (f == NULL) {
		perror("Error opening signed certificate file for write access");
	}
	else {
		rc = fwrite(certbuffer.data, 1, certbuffer.length, f);
		if (rc == certbuffer.length) {
			printf("Signed certificate written to file, %s\n", certfn);
		}
		else {
			perror("Error writing signed certificate to file");
		}
		fclose(f);
	}
	printf(" \n");
	gsk_free_buffer(&certbuffer);

	return 0;
}
