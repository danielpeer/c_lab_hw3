
import socket
import sys

global counter
counter=0
message="HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n"
address="/counter"

def find_get_index(lst) :
    for index in range(len(lst)):
        if lst[index] == "GET":
            return index

if __name__ == "__main__":

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('localhost',sys.argv[1]))
    data = s.recv(1024)
    lines_list = data.split("\r\n")
    first_line_word=lines_list[0].split()
    get_index = find_index(data_list)
    if lst[get_index+1] == address:
        counter += 1
        num_of_requests=str(counter)
        s.send(message%(len(num_of_requests),num_of_requests)) 
