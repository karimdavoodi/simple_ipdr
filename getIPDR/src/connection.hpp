
class Tcp_server {
    private:
        int port;
    public:
        Tcp_server(int _port):port(_port){}
        bool init();
        int  accept();
        ~Tcp_server();
};
