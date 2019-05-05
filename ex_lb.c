#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>

#define MESSAGE_SIZE 4096
#define MAX_NUMBER_OF_PENDING_CONNECTIONS 9
#define SERVER_PORT_FILE "server_port"
#define HTTP_PORT_FILE "http_port"
#define RUN_PROGRAM 1

void set_socket_port_and_bind(struct sockaddr_in *server_ip_addr, uint16_t *port, int *listen_fd)
{
    if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Error: server could not open socket.");
        exit(EXIT_FAILURE);       
    }
    socklen_t addrsize = sizeof(struct sockaddr_in);
    (*server_ip_addr).sin_family = AF_INET;
    (*server_ip_addr).sin_addr.s_addr = htonl(INADDR_ANY);
    (*server_ip_addr).sin_port = htons(*port);
    if(bind((*listen_fd), (struct sockaddr *) server_ip_addr, addrsize) != 0){ 
        set_socket_port_and_bind(server_ip_addr, port, listen_fd);
    }
}

void listen_to_socket(int listen_fd)
{
    if(listen(listen_fd, MAX_NUMBER_OF_PENDING_CONNECTIONS) != 0){ 
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

int main()
{
    struct sockaddr_in server_ip_addr; 
    struct sockaddr_in clients_ip_addr;
    struct sockaddr_in browser_ip_addr;
    uint16_t server_port;
    uint16_t http_port;
    int browser_listen_fd, clients_listen_fd, connected_clients_fd, connected_browser_fd, rc;
    char http_message[MESSAGE_SIZE + 1]; //// will change later
    char returned_message[MESSAGE_SIZE + 1]; //// will change later
    unsigned int number_to_write_back, num_digits;
    http_message[MESSAGE_SIZE] = '\0';
    returned_message[MESSAGE_SIZE] = '\0';
    socklen_t addrsize = sizeof(struct sockaddr_in); // i set him twice - find fix

    set_socket_port_and_bind(&server_ip_addr, &server_port, &clients_listen_fd);
    listen_to_socket(clients_listen_fd);
    write_port_to_file(server_port, SERVER_PORT_FILE);
    set_socket_port_and_bind(&server_ip_addr, &http_port, &browser_listen_fd);
    listen_to_socket(browser_listen_fd);
    write_port_to_file(http_port, HTTP_PORT_FILE);
    connected_clients_fd = accept(clients_listen_fd, (struct sockaddr *) &clients_ip_addr, &addrsize);
    connected_browser_fd = accept(browser_listen_fd, (struct sockaddr *) &browser_ip_addr, &addrsize); 
    if(connected_clients_fd < 0 || connected_browser_fd < 0){
        printf("Error: accept Failed: %s \n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    
    while(RUN_PROGRAM){
        
        number_to_write_back = 0; /*initilize for every new client*/  
        rc = read(connected_browser_fd, http_message, MESSAGE_SIZE);
        while(rc > 0){ 
            http_message[rc] = '\0'; 
            rc = read(connected_browser_fd, http_message, MESSAGE_SIZE);
            //// here do something like:
            // if got end of http request:
            //  send http to clients
            //  wait for responde
            //  send responde back to browser
            //  go back to reading from browser
        }
        if(rc == -1){
            printf("Error: read failed: %s \n", strerror(errno));
            close(connected_browser_fd);
            exit(EXIT_FAILURE);
        }
        else{ /*rc == 0*/
            num_digits = find_int_len(number_to_write_back);
            sprintf(returned_message, "%u", number_to_write_back); /*insert our return value to a buffer*/
            returned_message[num_digits] = '\0';
            if((rc = write(connected_browser_fd, returned_message, num_digits)) == -1){ /*try to write back to the browser*/
                perror("Error: failed to write back to client");
                close(connected_browser_fd);
                exit(EXIT_FAILURE);
            }
        }
    }
    close(connected_clients_fd);
    close(connected_browser_fd); 
}

///////////////////////////////////////////////////////////////////
unsigned int find_int_len(unsigned int x) {
    if (x >= 1000000000) return 10;
    if (x >= 100000000)  return 9;
    if (x >= 10000000)   return 8;
    if (x >= 1000000)    return 7;
    if (x >= 100000)     return 6;
    if (x >= 10000)      return 5;
    if (x >= 1000)       return 4;
    if (x >= 100)        return 3;
    if (x >= 10)         return 2;
    return 1;
}