#include <iostream>
#include "ini_file.hpp"
#include "ipdr_log.hpp"
#include "tcp_server.hpp"
#include "error.hpp"
#define PORT 8000
#define CONF_PATH "test/ini.conf"
using namespace std;

int main()
{
    Ipdr_log iplog;
    Ini_file ini(CONF_PATH);
    Tcp_server server(PORT);
    Log::log(0, "Log level: " + to_string(Log::LEVEL));
    if( !server.init() ) {
        Log::log(0, "Can't bind in port " + to_string(PORT));
    }
    if( !ini.isOk()){
        Log::log(0, "Can't read config  file:" + string(CONF_PATH));
    }
    while(true){
        try{
            if(server.client_accept()){
                string in = server.client_read();
                if(iplog.getArgs(in)){
                    if(ini.auth(iplog.getUser(),iplog.getPass())){
                        if(iplog.search(ini.logPath())){
                            server.client_write(iplog.getResults());
                        }else{
                            server.client_write("Not found");
                        }
                    }else{
                        server.client_write("Invalid Auth");
                    }
                }else{
                    server.client_write("Invalid Args");
                }
                server.client_close();
            }
        }catch(exception &e){
            Log::log(0, "Exception:" + string(e.what()));
        }
    }
    return 0;
}
