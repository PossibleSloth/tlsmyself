#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "gnutls/gnutls.h"

#define KEYFILE "testkey"
#define CERTFILE "servercert"
#define CAFILE "rootcert"

#define BUFSIZE 2048

int client_to_server[2];
int server_to_client[2];

int msg_num;

int test_msg;
int is_server_test;
int is_client_test;

FILE* input_file;


ssize_t server_push(gnutls_transport_ptr_t ptr, const void* data, size_t len);
ssize_t server_pull(gnutls_transport_ptr_t ptr, void* data, size_t maxlen);

ssize_t client_push(gnutls_transport_ptr_t ptr, const void* data, size_t len);
ssize_t client_pull(gnutls_transport_ptr_t ptr, void* data, size_t maxlen);

time_t stuck_time()
{
	return 2863311530;
}

int main(int argc, char *argv[]) {
	int result;
	pid_t pid;
	unsigned int pk_bits;
	gnutls_dh_params_t dh_params;
	
	is_server_test = 0;
	is_client_test = 0;
	
	test_msg = 0;
	
	if (argc == 4) {
		if (strncmp(argv[1], "-s", 2) == 0) 		is_server_test = 1;
		else if (strncmp(argv[1], "-c", 2) == 0)	is_client_test = 1;
		
		test_msg = atoi(argv[2]);
		
		input_file = fopen(argv[3], "r");
	}
	
	msg_num = 0;

	
	gnutls_session_t client_session;
	gnutls_session_t server_session;
	gnutls_certificate_credentials_t x509_cred;

	
	// Initialize GNUTLS and add test certificates
	result = gnutls_global_init();
	gnutls_global_set_time_function(stuck_time);
	
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM);
	
	
	pk_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_MEDIUM);

	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, pk_bits);
	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	// Initialize the server session
	gnutls_init(&server_session, GNUTLS_SERVER);
	gnutls_credentials_set(server_session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_certificate_server_set_request(server_session, GNUTLS_CERT_IGNORE);
	gnutls_set_default_priority(server_session);
	gnutls_transport_set_push_function(server_session, server_push);
	gnutls_transport_set_pull_function(server_session, server_pull);
	
	gnutls_handshake_set_timeout(server_session, 0);
	
	//Initialize the client session
	gnutls_init(&client_session, GNUTLS_CLIENT);
	gnutls_credentials_set(client_session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_set_default_priority(client_session);
	gnutls_transport_set_push_function(client_session, client_push);
	gnutls_transport_set_pull_function(client_session, client_pull);
	
	// No timeout for handshake
	gnutls_handshake_set_timeout(client_session, 0);
		
	#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
	#endif
	
	pipe(client_to_server);
	pipe(server_to_client);
	
	pid = fork();
	
	if (pid == 0)
	{
		// Running server session
    	close(client_to_server[1]);
		close(server_to_client[0]);
	
		do {
        	result = gnutls_handshake(server_session);
		} while ( result != 0 && !gnutls_error_is_fatal(result) );	
	}
	else
	{
		close(server_to_client[1]);    	
    	close(client_to_server[0]);

		do {
        	result = gnutls_handshake(client_session);
		} while ( result != 0 && !gnutls_error_is_fatal(result) );
	}
	
	return 0;
}

ssize_t server_push(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	msg_num++;
	if (!(is_server_test || is_client_test)) {
		char filename[20];
		FILE *fd;
		memset(filename, '\0', 20);
	

		snprintf(filename, 20, "saved/server-%d", msg_num);
		fd = fopen(filename, "wb");
		fwrite(data, len, 1, fd);
		fclose(fd);
	}
	
	ssize_t result;
	
	if (is_server_test && msg_num == test_msg) {
		char buffer[1600];
		result = fread(buffer, len, 1, input_file);
		result = write(server_to_client[1], buffer, len);
	}
	
	else {
		result = write(server_to_client[1], data, len);
	}

	nanosleep((const struct timespec[]){{0, 5L}}, NULL);
	return result;
	
}

ssize_t server_pull(gnutls_transport_ptr_t ptr, void* data, size_t maxlen)
{
	ssize_t result;	
	result = read(client_to_server[0], data, maxlen);

	nanosleep((const struct timespec[]){{0, 5L}}, NULL);
	return result;
}

ssize_t client_push(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	msg_num++;
	if (!(is_server_test || is_client_test)) {
		char filename[20];
		FILE *fd;
		memset(filename, '\0', 20);
	

		snprintf(filename, 20, "saved/client-%d", msg_num);

		fd = fopen(filename, "wb");
		fwrite(data, len, 1, fd);
		fclose(fd);
	}

	ssize_t result;
	
	if (is_client_test && msg_num == test_msg) {
		char buffer[1600];
		result = fread(buffer, len, 1, input_file);
		result = write(client_to_server[1], buffer, len);
	}
	
	else {
		result = write(client_to_server[1], data, len);
	}
	
	nanosleep((const struct timespec[]){{0, 5L}}, NULL);
	return result;
}

ssize_t client_pull(gnutls_transport_ptr_t ptr, void* data, size_t maxlen)
{
	ssize_t result;
	result = read(server_to_client[0], data, maxlen);
	nanosleep((const struct timespec[]){{0, 5L}}, NULL);
	return result;
}

