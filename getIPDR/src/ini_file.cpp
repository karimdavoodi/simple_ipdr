#include "ini_file.hpp"
#include "error.hpp"


bool Ini_file::auth(const std::string user,const std::string pass)
{
    std::string line;
    ini.seekg(0, std::ios::beg);
    std::string user_pass = "user=" + user + ":" + pass;
    while(ini >> line){
        if(line.find(user_pass) != std::string::npos){
            return true;
        }
    }
    Log::log(0, "Auth invalid user:[" + user +
            "] pass:[" + pass + "]");
    return false;
}
std::string Ini_file::logPath()
{
    std::string line;
    ini.seekg(0, std::ios::beg);
    while(ini >> line){
        if(line.find("path=") != std::string::npos){
            return line.substr(line.find("=") + 1);
        }
    }
    Log::log(0, "Not log path");
    return "";
}
