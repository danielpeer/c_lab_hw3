#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MESSAGE_SIZE 4096
#define MAX_NUMBER_OF_PENDING_CLIENT_CONNECTIONS 9

#define NUMBER_OF_SERVERS 3
#define MIN_PORT_ADDRESS 1024
#define MAX_PORT_ADDRESS 64000
#define SERVER_PORT_FILE "server_port"
#define HTTP_PORT_FILE "http_port"
#define HTTP_MESSAGE_SUFFIX "\r\n\r\n"
#define RUN_PROGRAM 1

// ASK IN FORUM ABOUT ALL EXIT'S - if no exits allwoed, then what to do upon failure?

void set_socket_port_and_bind(struct sockaddr_in *lb_ip_addr, uint16_t *port, int *listen_fd, 
                              socklen_t addrsize)
{
    int successfull_bind_flag = 0;
    if(((*listen_fd) = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("Error: server could not open socket.\n");
        exit(EXIT_FAILURE);       
    }
    (*lb_ip_addr).sin_family = AF_INET;
    (*lb_ip_addr).sin_addr.s_addr = htonl(INADDR_ANY);
    while(!successfull_bind_flag){
        (*port) = (rand() % (MAX_PORT_ADDRESS + MIN_PORT_ADDRESS + 1)) + MIN_PORT_ADDRESS;
        (*lb_ip_addr).sin_port = htons(*port);
        if(bind((*listen_fd), (struct sockaddr *) lb_ip_addr, addrsize) == 0){ 
            successfull_bind_flag = 1;
        }
    }
}

void listen_to_socket(int listen_fd, int max_pending_connections)
{
    if(listen(listen_fd, max_pending_connections) != 0){ 
        printf("Error: Listen Failed: %s \n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void write_port_to_file(uint16_t port, char *file_name)
{
    FILE *file = fopen(file_name ,"w");
    if (file == NULL) {
        printf ("Error in creating a file.\n");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%u", port);
    fclose (file);
}

void accept_server_connections(int servers_listen_fd, struct sockaddr_in servers_ip_addr, socklen_t addrsize,
                               int *connected_servers_fd)
{
    int fd_index;
    for(fd_index = 0; fd_index < NUMBER_OF_SERVERS; fd_index++){
        connected_servers_fd[fd_index] = \
            accept(servers_listen_fd, (struct sockaddr *) &servers_ip_addr, &addrsize);
        if(connected_servers_fd[fd_index] < 0 ){
            printf("Error: accept Failed: %s \n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }   
}

void accept_and_handle_browser_connection(int browser_listen_fd, socklen_t addrsize, 
                                          int *connected_servers_fd)
{
    struct sockaddr_in browser_ip_addr;

    char *http_message = malloc(MESSAGE_SIZE * sizeof(char)); //// will change later
    http_message[MESSAGE_SIZE - 1] = '\0'; // minus 1 may cause issues
    char *servers_message = malloc(MESSAGE_SIZE * sizeof(char)); //// will change later
    servers_message[MESSAGE_SIZE - 1] = '\0'; // minus 1 may cause issues

    int connected_browser_fd, message_size_bytes, bytes_read, number_processed_requests = 0;
    while(RUN_PROGRAM){
        // in operating systems class the accept was in the loop, but why here, same browser. but different
        // clients maybe ?
        if((connected_browser_fd = accept(browser_listen_fd, (struct sockaddr *) &browser_ip_addr, 
                                          &addrsize)) < 0){
            printf("Error: accept with browser Failed: %s \n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        message_size_bytes = 0; /*initilize for every new client*/  
        while(RUN_PROGRAM){ 
            bytes_read = recv(connected_browser_fd, http_message, MESSAGE_SIZE, 0);
            message_size_bytes += bytes_read;
            if((bytes_read > 0) && (bytes_read < MESSAGE_SIZE) && strstr(http_message, HTTP_MESSAGE_SUFFIX)){
                http_message[bytes_read] = '\0';
                //// here do something like:
                // if got end of http request:
                //  send http to clients
                //  wait for responde
                //  send responde back to browser
                //  go back to reading from browser
            }
            
            if(bytes_read == -1){
                printf("Error: read failed: %s \n", strerror(errno));
                close(connected_browser_fd);
                close(connected_servers_fd);
                exit(EXIT_FAILURE);
            } else{ 
                /*
                bytes_read = 0
                sprintf(servers_message, "%u", number_to_write_back); 
                returned_message[num_digits] = '\0';
                if((rc = write(connected_browser_fd, returned_message, num_digits)) == -1){ 
                    printf("Error: failed to write back to client.\n");
                    close(connected_browser_fd);
                    close(connected_servers_fd);
                    exit(EXIT_FAILURE);
                }
                */
            }
        }
        //pass request to sever number: number_processed_requests % NUMBER_OF_SERVERS
    }
    close(connected_browser_fd);
}

int main()
{
    struct sockaddr_in lb_ip_addr; 
    struct sockaddr_in servers_ip_addr;
    
    uint16_t server_port;
    uint16_t http_port;
    int connected_servers_fd[NUMBER_OF_SERVERS];
    int browser_listen_fd, servers_listen_fd, fd_index;
    srand(time(NULL));
    
    socklen_t addrsize = sizeof(struct sockaddr_in); 

    // three different functions may be combined to one.
    set_socket_port_and_bind(&lb_ip_addr, &server_port, &servers_listen_fd, addrsize);
    listen_to_socket(servers_listen_fd, NUMBER_OF_SERVERS);
    write_port_to_file(server_port, SERVER_PORT_FILE);
    
    set_socket_port_and_bind(&lb_ip_addr, &http_port, &browser_listen_fd, addrsize);
    listen_to_socket(browser_listen_fd, MAX_NUMBER_OF_PENDING_CLIENT_CONNECTIONS);
    write_port_to_file(http_port, HTTP_PORT_FILE);

    // maybe put server_connections inside the loops? 
    accept_server_connections(servers_listen_fd, servers_ip_addr, addrsize, connected_servers_fd);
    accept_and_handle_browser_connection(browser_listen_fd, addrsize, connected_servers_fd); 
    for (fd_index = 0; fd_index < NUMBER_OF_SERVERS; fd_index++){
       close(connected_servers_fd[fd_index]);
    } 
}