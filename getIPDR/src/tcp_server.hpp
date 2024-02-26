#include<iostream>
#define READ_SIZE 4096

class Tcp_server {
    private:
        int port;
        int server_fd;
        int client_fd;
    public:
        Tcp_server(int _port):
            port(_port),
            server_fd(-1),
            client_fd(-1){}
        bool init();
        bool client_accept();
        std::string client_read();
        bool client_write(const std::string);
        void client_close();
        ~Tcp_server();
};
