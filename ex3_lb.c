#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MESSAGE_SIZE 4096
#define MAX_NUMBER_OF_PENDING_CLIENT_CONNECTIONS 9
#define OFF 0
#define ON 1
#define ERROR_OCCURED -1
#define NUMBER_OF_SERVERS 3
#define MIN_PORT_ADDRESS 1024
#define MAX_PORT_ADDRESS 64000
#define NULL_TERMINATOR '\0'
#define SERVER_PORT_FILE "server_port"
#define HTTP_PORT_FILE "http_port"
#define HTTP_MESSAGE_SUFFIX "\r\n\r\n"
#define RUN_PROGRAM 1

void set_socket_port_and_bind(struct sockaddr_in *lb_ip_addr, short unsigned int *port, int *listen_fd,
                              socklen_t addrsize)
{
  int successfull_bind_flag = OFF, reuse_addr = 1;
  (*listen_fd) = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt((*listen_fd), SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
  (*lb_ip_addr).sin_family = AF_INET;
  (*lb_ip_addr).sin_addr.s_addr = htonl(INADDR_ANY);
  while (!successfull_bind_flag) {
    (*port) = (rand() % (MAX_PORT_ADDRESS + MIN_PORT_ADDRESS + 1)) + MIN_PORT_ADDRESS;
    (*lb_ip_addr).sin_port = htons(*port);
    if (bind((*listen_fd), (struct sockaddr *)lb_ip_addr, addrsize) == 0) {
      successfull_bind_flag = ON;
    }
  }
}

void write_port_to_file(int port, char *file_name)
{
  FILE *file = fopen(file_name, "w");
  if (file == NULL) {
    printf("Error in creating a file.\n");
  }
  fprintf(file, "%d", port);
  fclose(file);
}

void close_server_connections(int *connected_servers_fd)
{
  int fd_index;
  for (fd_index = 0; fd_index < NUMBER_OF_SERVERS; fd_index++) {
    close(connected_servers_fd[fd_index]);
  }
}

void accept_server_connections(int servers_listen_fd, int *connected_servers_fd)
{
  int fd_index;
  for (fd_index = 0; fd_index < NUMBER_OF_SERVERS; fd_index++) {
    connected_servers_fd[fd_index] = accept(servers_listen_fd, NULL, NULL);
  }
}

void send_http_message_to_connection(int reciveing_fd, char *message_to_send, int message_to_send_size_bytes)
{
  int bytes_sent, total_amount_of_bytes_sent = 0;
  while ((bytes_sent = send(reciveing_fd, message_to_send + total_amount_of_bytes_sent,
                            message_to_send_size_bytes - total_amount_of_bytes_sent, 0)) > 0) {
    total_amount_of_bytes_sent += bytes_sent;
    if (total_amount_of_bytes_sent == message_to_send_size_bytes) {
      break;
    }
  }
  if (bytes_sent == -1) {
    printf("Error: send failed: %s \n", strerror(errno));
  }
}

int get_http_message_from_connection(int connections_fd, char *http_message)
{
  int message_allocated_memory_size_bytes, message_size_bytes, bytes_read;
  char message_read_buffer[MESSAGE_SIZE];
  message_read_buffer[MESSAGE_SIZE - 1] = NULL_TERMINATOR;
  message_allocated_memory_size_bytes = MESSAGE_SIZE;
  message_size_bytes = 0;
  while ((bytes_read = recv(connections_fd, message_read_buffer, MESSAGE_SIZE - 1, 0)) > 0) {
    message_size_bytes += bytes_read;
    if (message_size_bytes > message_allocated_memory_size_bytes) {
      http_message = (char *)realloc(http_message, message_allocated_memory_size_bytes + MESSAGE_SIZE);
      message_allocated_memory_size_bytes += MESSAGE_SIZE;
    }
    strncpy(http_message + message_size_bytes - bytes_read, message_read_buffer, bytes_read);
    http_message[message_size_bytes] = NULL_TERMINATOR;
    if (strstr(http_message, HTTP_MESSAGE_SUFFIX) != NULL) {
      return message_size_bytes;
    }
  }
  if (bytes_read == -1) {
    printf("Error: recv failed: %s \n", strerror(errno));

  } else {
    printf("Error: recv finished getting message - but message is not complete\n");
  }
  return ERROR_OCCURED;
}

int send_request_and_get_response(int number_processed_requests, const int *connected_servers_fd, char *http_message,
                                  int message_size_bytes, char *http_response)
{
  int handling_server_fd, bytes_read;
  handling_server_fd = connected_servers_fd[number_processed_requests % NUMBER_OF_SERVERS];
  send_http_message_to_connection(handling_server_fd, http_message, message_size_bytes);
  bytes_read = get_http_message_from_connection(handling_server_fd, http_response);
  return bytes_read;
}

void accept_and_handle_browser_connection(int browser_listen_fd, int *connected_servers_fd)
{
  char *http_request;
  char *http_response;
  int connected_browser_fd, response_message_size_bytes, request_message_size_bytes, number_processed_requests = -1;
  while (RUN_PROGRAM) {
    connected_browser_fd = accept(browser_listen_fd, NULL, NULL);
    http_request = (char *)malloc(MESSAGE_SIZE * sizeof(char));
    http_request[MESSAGE_SIZE - 1] = NULL_TERMINATOR;
    request_message_size_bytes = get_http_message_from_connection(connected_browser_fd, http_request);
    number_processed_requests++;

    http_response = (char *)malloc(MESSAGE_SIZE * sizeof(char));
    http_response[MESSAGE_SIZE - 1] = NULL_TERMINATOR;
    response_message_size_bytes = send_request_and_get_response(
        number_processed_requests, connected_servers_fd, http_request, request_message_size_bytes, http_response);
    send_http_message_to_connection(connected_browser_fd, http_response, response_message_size_bytes);
    free(http_request);
    free(http_response);
    close(connected_browser_fd);
  }
}

void set_connection_credentials(struct sockaddr_in *lb_ip_addr, short unsigned int *port, int *listen_fd,
                                int max_number_of_pending_connections, char *port_file_name)
{
  socklen_t addrsize = sizeof(struct sockaddr_in);
  set_socket_port_and_bind(lb_ip_addr, port, listen_fd, addrsize);
  listen((*listen_fd), max_number_of_pending_connections);
  write_port_to_file((int)(*port), port_file_name);
}

int main()
{
  struct sockaddr_in lb_ip_addr;
  int connected_servers_fd[NUMBER_OF_SERVERS];
  short unsigned int server_port, http_port;
  int browser_listen_fd, servers_listen_fd;
  srand(time(NULL));
  set_connection_credentials(&lb_ip_addr, &server_port, &servers_listen_fd, NUMBER_OF_SERVERS, SERVER_PORT_FILE);
  set_connection_credentials(&lb_ip_addr, &http_port, &browser_listen_fd, MAX_NUMBER_OF_PENDING_CLIENT_CONNECTIONS,
                             HTTP_PORT_FILE);
  accept_server_connections(servers_listen_fd, connected_servers_fd);
  accept_and_handle_browser_connection(browser_listen_fd, connected_servers_fd);
  close_server_connections(connected_servers_fd);
  return EXIT_SUCCESS;
}
