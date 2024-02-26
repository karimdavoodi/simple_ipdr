#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include "error.hpp"
#include "tcp_server.hpp"
using namespace std;

bool Tcp_server::init()
{
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
        throw Error_socket("Open socket");
    }
    int optval = 1;
    struct sockaddr_in serveraddr;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
            (const void *)&optval , sizeof(int));

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short) port );

    optval = 0;
    if(bind(server_fd, (struct sockaddr *) &serveraddr, 
                sizeof(serveraddr)) < 0){ 
        close(server_fd);
        server_fd = -1;
        throw Error_socket("Socket bind");
    }
    if (listen(server_fd, 20) < 0){
        close(server_fd);
        server_fd = -1;
        throw Error_socket("Socket listen");
    }
    Log::log(0, "Listen in port:" + to_string(port));
    return true;
}
bool Tcp_server::client_accept()
{
    struct sockaddr_in client_sock;
    socklen_t sock_len = sizeof(struct sockaddr_in);
    
    if(server_fd == -1) throw Error_socket("Invalid server_fd");
    client_fd = accept(server_fd, 
                (struct sockaddr *) &client_sock, 
                &sock_len);
    if(client_fd <= 0) throw Error_socket("Accept error");
    Log::log(1, "Accepted client");
    return true;
}
std::string Tcp_server::client_read()
{
    char buff[READ_SIZE];

    if(client_fd < 0) throw Error_socket("read on ready client");
    size_t n = read(client_fd, buff, READ_SIZE);
    if(n <= 0 )  return "";
    string in = string(buff);
    Log::log(1, "Read from Client:" + in);
    return in;
}
bool Tcp_server::client_write(const std::string out)
{
    int n = write(client_fd, out.c_str(), out.size());
    if(n < 0) return false;
    Log::log(1, "Write to client sizet:" + out );
    return true;
}
void Tcp_server::client_close()
{
    if(client_fd > 0) close(client_fd);
}
Tcp_server::~Tcp_server()
{
    if(server_fd > 0) close(server_fd);
}
