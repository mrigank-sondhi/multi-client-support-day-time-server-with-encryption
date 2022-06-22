/*
Command line arguments:
argv[0] = filename
argv[1] = server ipaddress
argv[2] = port number
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h> //for using openssl functions and certificates and also configuring them
#include <openssl/err.h> //helps to find out openssl errors

void error(const char *message)
{
	perror(message);
	exit(1);
}

SSL_CTX *initialize_CTX(void) // used for creating and setting up the ssl context structure
{
	const SSL_METHOD *m;
	SSL_CTX *ctx;				  // The SSL_CTX object uses method as the connection method
	OpenSSL_add_all_algorithms(); // used to load and register all the cryptos
	SSL_load_error_strings();	  // used to load all the error messages
	m = TLS_client_method();	  // used to create a new instance of client-method which is a general-purpose and version-flexible SSL/TLS method
	ctx = SSL_CTX_new(m);		  // used to create a new context from the above created method; used to create a new SSL_CTX object as a framework to establish TLS/SSL enabled connections

	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void certificate_displayer(SSL *ssl) // show the certificates to the server and match them; but in this case we are not using any client certificate
{
	X509 *certificate;
	char *l;
	certificate = SSL_get_peer_certificate(ssl); // get the server's certificate

	if (certificate != NULL)
	{
		printf("Server certificates are as follows:\n");
		l = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0);
		printf("Subject: %s\n", l);

		free(l);

		l = X509_NAME_oneline(X509_get_issuer_name(certificate), 0, 0);
		printf("Issuer: %s\n", l);
		free(l);

		X509_free(certificate);
	}

	else
	{
		printf("No client certificates have been configured.\n");
	}
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx;
	SSL *ssl;
	int client_socket, port_number;
	struct sockaddr_in server_address;
	struct hostent *server;
	char buf[1024];

	if (argc < 3)
	{
		fprintf(stderr, "Usage is: %s hostname port\n", argv[0]);
		exit(1);
	}
	port_number = atoi(argv[2]);
	SSL_library_init();		// initialize the library and load the encryption and hashing algorithms present in ssl
	ctx = initialize_CTX(); // this SSL_CTX object, is created as a framework to establish TLS/SSL enabled connections

	//-----------------------------------------------------------------------creating a socket------------------------------------------------
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket < 0)
	{
		error("[-]Error opening socket.\n");
	}
	printf("[+]Client Socket is created.\n");

	server = gethostbyname(argv[1]);
	if (server == NULL)
	{
		fprintf(stderr, "[-]Error, no such host.");
	}

	//------------------------------------------------------defining server address------------------------------------------------------------
	memset(&server_address, '\0', sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port_number);
	bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);

	//------------------------------------------------connecting to server---------------------------------------------------------------------
	if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
	{
		error("[-]Error in connection.\n");
	}
	printf("[+]Connected to Server.\n");
	ssl = SSL_new(ctx); // get a new SSL state with context; SSL_new() creates a new SSL structure which is needed to hold the data for a TLS/SSL connection

	printf("\nEnter:\n1)request: to retrieve date and time\n2)exit: to exit the session\n");
	SSL_set_fd(ssl, client_socket); // attach the socket descriptor; when a network connection has been created, this can be used to assign it to an SSL object; SSL_set_fd() sets the file 	descriptor fd as the input/output facility for the TLS/SSL (encrypted) side of ssl

	//-------------------------------------------communicate with the server-------------------------------------------------------------------
	if (SSL_connect(ssl) < 0) // perform the connection; initiate the TLS/SSL handshake with a TLS/SSL server
		ERR_print_errors_fp(stderr);
	else
	{
		printf("Connected with encryption: %s\n", SSL_get_cipher(ssl));
		certificate_displayer(ssl); // get certificates

		// const SSL_SESSION *session = SSL_get_session(ssl);
		// BIO *fp = BIO_new_fp(stdout, BIO_NOCLOSE);
		// SSL_SESSION_print(fp, session);

		while (1)
		{
			bzero(buf, 1024);
			printf("Client: ");
			scanf("%s", &buf[0]);

			// encrypt and send the message
			if (SSL_write(ssl, buf, strlen(buf)) <= 0)
			{
				error("[-]Error in sending data.\n");
			}

			// if exit then disconnect from server
			if (strcmp(buf, "end") == 0)
			{
				close(client_socket);
				printf("[-]Disconnected from server.\n");
				exit(1);
			}

			else if (strcmp(buf, "daytime") == 0)
			{
				bzero(buf, 1024);
				// if received -1, show error otherwise decrypt received message and show day, date and time
				if (SSL_read(ssl, buf, sizeof(buf)) <= 0)
				{
					printf("[-]Error in receiving data.\n");
				}
				else
				{
					printf("Server: %s\n", buf);
				}
			}

			else
			{
				// if received -1, show error otherwise decrypt received message and show invalid request
				if (SSL_read(ssl, buf, sizeof(buf)) <= 0)
				{
					printf("[-]Error in receiving data.\n");
				}
				else
				{
					printf("Server: %s\n", buf);
				}
				printf("[-]Enter correct request.\n");
			}
		}
		SSL_free(ssl); // release the connection state
	}
	close(client_socket); // close the socket
	SSL_CTX_free(ctx);	  // release the context
	return 0;
}
