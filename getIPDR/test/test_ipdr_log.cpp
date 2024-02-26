#include<catch.hpp>

#include "../src/tcp_server.hpp"
#include "../src/ipdr_log.hpp"
#include "../src/ini_file.hpp"
using namespace std;
/*
 *  connect - get args - search log - put result - disconnect
 *  ini_file
 * */

TEST_CASE("Test of Connection","[connection]"){
    Tcp_server server(8000);
    REQUIRE( server.init() == true );
    //REQUIRE( server.accept_client() > 0 );
}

TEST_CASE("Test of IPDR Log","[log]"){
    std::string arg = 
        "?TelNum=12431"
        "&IPAddr=18d6c7c918b2"
        "&CId=1310703842"
        "&FDate=1575105942"
        "&TDate=1575106042"
        "&Uname=admin0"
        "&AutStr=123";
    Ipdr_log iplog;
    Ini_file ini("test/ini.conf");

    REQUIRE( ini.isOk() == true );
    REQUIRE( ini.logPath() == "/home/karim/src/mysrc/ipdr_log/test/log");
    REQUIRE( iplog.getArgs("GET /GetIPDR" + arg) == true );
    REQUIRE( ini.auth(iplog.getUser(), iplog.getPass()) == true );
    REQUIRE( iplog.search(ini.logPath()) == true);
    REQUIRE( iplog.getResults() == "");
}
