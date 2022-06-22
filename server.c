#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h> //for using openssl functions and certificates and also configuring them
#include <openssl/err.h> //helps to find out openssl errors

#define MAX_CLIENTS 20

void error(const char *message)
{
	perror(message);
	exit(1);
}

//to check whether the root user is executing the server or not
//only the root user can be the server
int check_if_root() 
{
	if (getuid() != 0)
	{
		//if its not the root user return 0
		return 0;
	}
	else
	{
		//if its not the root user return 1
		return 1; 
	}
}

//to create and set up the SSL context structure
SSL_CTX *init_the_server_CTX(void) 
{
	const SSL_METHOD *m;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms(); //used to load and register all the cryptos
	SSL_load_error_strings(); //used to load all the error messages
	m = TLS_server_method(); //used to create a new instance of server-method
	ctx = SSL_CTX_new(m); //used to create a new context from above created method

	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

//to load the created SSL certificates into a SSL_CTX structure
void certificate_loader(SSL_CTX *ctx, char *certificate_file, char *key_file)
{
	//used to set the local certificate from the certificate file of type .pem
	if (SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	//used to set the private key from the key file, this can be the same as the certificate file
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	//used to verify the private key obtained above
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "The Private Key does not match the Public Certificate.\n");
		abort();
	}
}

void certificate_displayer(SSL *ssl) //show the certificates to the client and match them
{
	X509 *certificate;
	char *l;

	certificate = SSL_get_peer_certificate(ssl); //Get the certificates if they are available
	if (certificate != NULL)
	{
		printf("The Certificates are as follows:\n");
		
		l = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0);
		printf("Server: %s\n", l); //server certifcates
		
		free(l);

		l = X509_NAME_oneline(X509_get_issuer_name(certificate), 0, 0);
		printf("Client: %s\n", l); //client certificates

		free(l);

		X509_free(certificate);
	}
	else
	{
		printf("No certificates are available.\n");
	}
}

int main(int argc, char* argv[])
{
	SSL_CTX *ctx;
	
	//show an error if the function returned a 0; which means user is not the root user 
	if (!check_if_root())
	{
		error("The server script must be run as the root/sudo user.");
	}
	
	if(argc < 2)
	{
		fprintf(stderr, "[-]Port number not provided. Program terminated.\n");
		exit(1);
	}	
	
	SSL_library_init(); //load the encryption and hashing algorithms present in SSL
	ctx = init_the_server_CTX();	//initialize SSL
	certificate_loader(ctx, "certificate.pem", "certificate.pem"); //load the certificates
		
	int socket_fd, port_number;
	struct sockaddr_in server_address;

	int new_socket;
	struct sockaddr_in new_address;

	socklen_t address_size;

	//size of message to be sent
	char buf[1024];
	pid_t child_process_id;

	//----------------------------------creating a socket-------------------------------------
	socket_fd = socket(AF_INET, SOCK_STREAM, 0); //socket_fd is a file descriptor
	if(socket_fd < 0)
	{
		error("[-]Error opening socket.\n");
	}
	printf("[+]Server Socket created.\n");

	memset(&server_address, '\0', sizeof(server_address));
	port_number = atoi(argv[1]);
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port_number); //host-to-network short
	server_address.sin_addr.s_addr = INADDR_ANY;

	//----------------------------------binding the socket-------------------------------------
	if(bind(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		error("[-]Error in binding.\n");
	}
	printf("[+]Bound to port %d\n", port_number);

	SSL *ssl;
	if(listen(socket_fd, MAX_CLIENTS) == 0)
	{
		printf("[+]Listening...\n");
	}
	else
	{
		error("[-]Error in binding.\n");
	}
	
	//-------------------------accepting the connection and communicating---------------------------------------
	while(1)
	{
		//--------------accept connections with new sockets until error-------------------------------------
		new_socket = accept(socket_fd, (struct sockaddr*)&new_address, &address_size);
		if(new_socket < 0)
		{
			exit(1);
		}
		printf("Connection accepted from %s:%d\n", inet_ntoa(new_address.sin_addr), ntohs(new_address.sin_port)); //print information of the connected client 

		ssl = SSL_new(ctx); //get new SSL state with context
		SSL_set_fd(ssl, new_socket); //set the connection socket to the SSL state
					 
		//--------------------------------------service the connection---------------------------------------------------
		int socket_descriptor;
		if (SSL_accept(ssl) < 0) // do the SSL-protocol accept; SSL_accept() will wait for a TLS/SSL client to initiate the TLS/SSL handshake
		{
			ERR_print_errors_fp(stderr);
		}
		else
		{
			certificate_displayer(ssl); //get certificates
			
			const SSL_SESSION *session = SSL_get_session(ssl); //returns the pointer to a SSL_SESSION object which contains information about the session
			BIO *fp = BIO_new_fp(stdout, BIO_NOCLOSE);
			SSL_SESSION_print(fp, session); //print SSL session information
			SSL_SESSION_print_keylog(fp, session); //print RSA session information	
				
			//the fork system call is used to create a new process
			if((child_process_id = fork()) == 0)
			{
				close(socket_fd);
				while(1)
				{
					//------------------receive messages from each socket until "end" command-------------------------
					if(SSL_read(ssl, buf, sizeof(buf)) <= 0) //receive and decrypt message from client
					{
						error("[-]Error in receiving data.\n");
					}
					
					if(strcmp(buf, "end") == 0)
					{
						printf("Disconnected from %s:%d\n", inet_ntoa(new_address.sin_addr), ntohs(new_address.sin_port));
						break;
					}
					else
					{
						printf("Client %d: %s\n", ntohs(new_address.sin_port), buf);
						if (strcmp(buf, "daytime") == 0) 
						{
							//Respond with "Day, Date and Time"
							time_t t;

	   						t = time(NULL);
	   						char res[100];
	   						strftime(res, sizeof(res), "%A %Y-%m-%d %H:%M:%S", localtime(&t));
	   						
	   						if(SSL_write(ssl, res, strlen(res)) <= 0) //encrypt the day, date and time and send it to the client
	   						{
	   							error("[-]Error in sending data.\n");
	   						}
							bzero(res, sizeof(res));
						}
						else 
						{
							//As no valid request was received, respond with "Invalid Request"
							char res[100];
							strcpy(res, "Invalid Request");
	   						if(SSL_write(ssl, res, strlen(res)) <= 0) //encrypt and send the message to the client
	   						{
	   							error("[-]Error in sending data.\n");
	   						}
							bzero(res, sizeof(res));
						}					
					}
					bzero(buf, sizeof(buf));
				}
			}
		}
		socket_descriptor = SSL_get_fd(ssl); //get the socket connection
		SSL_free(ssl); //release the SSL state
		close(socket_descriptor); //close the connection
	}
	close(new_socket);
	close(socket_fd); //close the server socket
	SSL_CTX_free(ctx); //release the context
	return 0;
}
