#include <iostream>
#include <fstream>
#include <regex>
#include <iterator>
#include <chrono>
#include <ctime>
#include <string>
#include <vector>
#include <cmath>
#include <memory>
#include <algorithm>
#include <boost/filesystem/operations.hpp>
#include "ipdr_log.hpp"
#include "error.hpp"
#define DEBUG
using namespace boost::filesystem;
using namespace std;

bool  Ipdr_log::getArgs(const std::string args)
{
    if(args.find("GET /GetIPDR?") == std::string::npos) 
        return false;
    auto begin = args.begin() + args.find("?") + 1;
    std::regex re("[& ]");
    std::sregex_token_iterator it(begin, args.end(), re, -1);
    std::sregex_token_iterator end;
    for(; it != end; ++it){
        std::string item = *it;
        if(item.find("=") == std::string::npos) continue;
        std::string val = item.substr(item.find("=")+1);
        if(item.find("TelNum=") != std::string::npos)
            in_args.tel = val;
        else if(item.find("IPAddr=") != std::string::npos)
            in_args.ip = val;
        else if(item.find("CId=") != std::string::npos)
            in_args.cid = val;
        else if(item.find("FDate=") != std::string::npos)
            in_args.f_date = val;
        else if(item.find("TDate=") != std::string::npos)
            in_args.t_date = val;
        else if(item.find("Uname=") != std::string::npos)
            in_args.user = val;
        else if(item.find("AutStr=") != std::string::npos)
            in_args.pass = val;
    }
    if( in_args.tel != "" &&
        in_args.ip != "" &&        
        in_args.cid != "" &&        
        in_args.user != "" &&        
        in_args.pass != "" &&        
        in_args.f_date != "" &&        
        in_args.t_date != ""  ){ 
        args_ok = true;
        return true;
    }
    return false;
}
bool Ipdr_log::files_list()
{
    time_t f_long = std::stol(in_args.f_date);
    struct tm *f_time = std::localtime(&f_long);
    f_time->tm_sec =  0;
    f_time->tm_min = floor(f_time->tm_min / 5) * 5;
    time_t start_t = mktime(f_time);

    time_t t_long = std::stol(in_args.t_date);
    struct tm *t_time = std::localtime(&t_long);
    t_time->tm_sec =  0;
    t_time->tm_min = ceil(t_time->tm_min / 5) * 5;
    time_t end_t = mktime(t_time);

    files.clear();
    result.clear();
    char time_str[100];
    if((t_long - f_long)/60 > 10 ) 
        throw Error_log("too mutch time distance");
    Log::log(1, "Start:" + in_args.f_date + 
            " End:" + in_args.t_date );
    for(; start_t <= end_t; start_t += 60*5){
        struct tm *cur_time = std::localtime(&start_t);
        std::strftime(time_str, 100,  "%Y%m%d%H%M_", cur_time);    
        files.push_back(std::string(time_str));
        Log::log(1, "File for search:" + string(time_str) );
    }
    struct tm *day_time = std::localtime(&start_t);
    std::strftime(time_str, 100, "%Y%m%d", day_time);    
    day_dir = string(time_str);
    if(files.size() == 0) 
        return false;
    return true;
}
shared_ptr< vector<string> > Ipdr_log::get_file_list(string _path)
{
    auto vec = make_shared< vector<string> >();
    Log::log(1, "Search dir: " + _path );
    try{
        for(auto dir: directory_iterator(_path)){
            std::string file_name = dir.path().string();
            vec->push_back(file_name);
            Log::log(2, "Search file: " + file_name );
        }    
        sort(vec->begin(), vec->end());
    }catch( std::exception &e ){
        throw Error_log("boot directory error:"  + string(e.what()));
    }
    Log::log(1, "Search dir: " + _path + 
            " found files number:" + to_string(vec->size()) );
    return vec;
}
bool Ipdr_log::search(std::string _path)
{
    path = _path;    
    if(args_ok == false){
        Log::log(0, "Args not OK");
        return false;
    }
    if(files_list() == false){
        Log::log(0, "Log file not find for that time");
        return false;
    }

    // Unzip log file to /tmp
    shared_ptr< vector<string> > tmp = get_file_list("/tmp");
    for(auto file: files ){
        bool find_in_tmp_dir = false;
        for(auto tmp_file: *tmp){
            if(tmp_file.find(file) != string::npos){
                find_in_tmp_dir = true;
                Log::log(1, "File found in /tmp:" + file);
                break;
            }
        }
        if(find_in_tmp_dir == false){
            Log::log(1, "File:" + file + " not found in /tmp"
                    " try to unzip ...");
            gunzip_to_tmp(file);
        }
    }
    // Search in files at /tmp
    Log::log(1, "Search Files number:" + to_string(files.size()));
    shared_ptr< vector<string> > tmp1 = get_file_list("/tmp");
    for(auto file: files ){
        for(auto tmp_file: *tmp1){
            if(tmp_file.find(file) != string::npos){
                Log::log(1, "Search in " + file );
                if(search_file(tmp_file)){
                    return true;
                }
                break;
            }
        }
    }
    Log::log(1, "Not find");
    return false;
}
bool Ipdr_log::search_file(std::string file_in_tmp)
{
    bool find_in_file = false;
    time_t f_long = std::stol(in_args.f_date);
    time_t t_long = std::stol(in_args.t_date);
    ifstream in_file(file_in_tmp);
    string line;
    if(!in_file.is_open())
        throw Error_log("Can't open file:" + file_in_tmp);
   
    string ip_hex = in_args.ip; // TODO: conver to hex
    regex re("\\|");
    Log::log(1, "Search in file:" + file_in_tmp);
    while( in_file >> line ){
        //7110807355|c4e98480d1ad|1575105943|17|||5EB7CDB6|
        //     21585|12C40F27|8812|||||
        if( line.find( in_args.cid) != 0){
            Log::log(3, "Not equal CID: " + line);
            continue;
        }
        if( line.find( ip_hex ) == string::npos ){
            Log::log(3, "Not equal IP HEX: " + line);
            continue;
        }
        std::sregex_token_iterator it(
                line.cbegin(), line.cend(), re, -1);
        std::sregex_token_iterator end;
        auto ts = it;  
        Log::log(3, "LINE:" + line);
        ts++; ts++;
        string timestamp = *ts;
        time_t t_curr = std::stol(timestamp);
        if(t_curr < f_long || t_curr > t_long){
            Log::log(3, "Not equal TIME DURATION: " + line +
                    " F:" + in_args.f_date +
                    " T:" + in_args.t_date  +
                    " C:" + timestamp);
            continue;
        }
        auto res = make_shared< vector<string>>(); 
        int i = 0;
        for(; it != end && i<FEILD_NUM; ++it,++i){
            Log::log(4, "FIELD:" + to_string(i)
                    + ":" + string(*it));
            res->push_back(*it);
        }
        for(; i<FEILD_NUM; ++i){
            res->push_back("");
        }
        if(i == FEILD_NUM){
            Log::log(3, "Find and save:" + line);
            result.push_back(res);
            find_in_file = true;
        }else 
            Log::log(1, "Invalid number of field: " + to_string(i));
        if(result.size() > MAX_RESULT) break;
    }
    return find_in_file;
}
bool Ipdr_log::gunzip_to_tmp(std::string file_pattern)
{
    string day_full_path = path + "/" + 
                            day_dir; 
    shared_ptr< vector<string> > day_files = 
        get_file_list(day_full_path);
    if(day_files->size() == 0){
        Log::log(0, "Don't find Day files!");
        return false;
    }
    for(auto file: *day_files ){
        Log::log(0, "search to unzip:" + file + 
                " for:" + file_pattern );
        if(file.find(file_pattern) != string::npos){
            std::string cmd = "gunzip " + file + 
                    " -c > /tmp/" + file_pattern;
            Log::log(1, "Run: " + cmd);
            std::system(cmd.c_str());
            return true;
        }
    }
    Log::log(0, "Not find to unzip!");
    return false;
}
std::string Ipdr_log::getResults()
{
    std::stringstream res;
    if(result.size() == 0)
        return "";
    for(auto str : result){
        if(str->size() != FEILD_NUM ) continue;
        vector<string> v = *str;
        for(size_t i=0; i<FEILD_NUM; ++i){
            res <<  "[" << i << "]" << v[i]  << "\n";
            str->pop_back();
        }
    }
    return res.str();
}
