# multi-client-support-day-time-server-with-encryption
This project implements a secure multi-client support day-time server which allows clients to seek the current day, date and time from the server.

1)Creating OpenSSL certificates:
	Command Line: $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout <KEYFILENAME>.pem -out <CERTIFICATEFILENAME>.pem
	Example: $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certificate.pem -out certificate.pem
	
2)Compiling server.c:
	Command Line: $ gcc -Wall -o <OUTPUTFILE> <INPUTFILE>.c -L/usr/lib -lssl -lcrypto
	Example: $ gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto
	
3)Executing server:
	Command Line: $ sudo ./<FILENAME> <PORTNUMBER>
	Example: $ sudo ./server 8000
	
4)Compiling client.c :
	Command Line: $ gcc -Wall -o <OUTPUTFILE> <INPUTFILE>.c -L/usr/lib -lssl -lcrypto
	Example: $ gcc -Wall -o client client.c -L/usr/lib -lssl -lcrypto
	
5)Executing client:
	1. If client and server are on the same computer and same network, loopback address can be passed instead of the IP address.
		Command Line: $ ./client <LOOPBACKADDRESS> <PORTNUMBER>
		Example: $ ./client 127.0.0.1 8000
	2. If client and server are on different computers but the same network, IP address needs to be passed.
		Command Line: $ ./client <IPADDRESS> <PORTNUMBER>
		Example: $ ./client 212.246.100.200 8000
			
6)The Client can request the following:
	"daytime": Client requests the server to send the current day, date and time in standard format.
	"end": Client disconnects from the server and ends the client process.
	
NOTE: 
1) A single Server currently supports 20 Clients (defined as MAX_CLIENTS in server.c). Multi-Client support was achieved using the fork() system call in the Server script to create child processes
of the Server to handle multiple Clients.
2) Unix network socket programming was used for communication between the Server and the Client on the same network. 
3) The "communication domain" used was "AF_INET", for communicating between processes on different hosts connected by IPV4.  
4) The "communication type" used was "SOCK_STREAM"; that is Transmission Control Protocol" (TCP) which is a reliable and a connection-oriented protocol.
5) The "protocol" used was "Internet Protocol (IP)".
6) Open SSL was used for AES encryption and for generating server certificates. Every client shared a unique session key for every session with the server.
