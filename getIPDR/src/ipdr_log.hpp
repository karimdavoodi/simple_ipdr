#include <iostream>
#include <vector>
#include <memory>
#define FEILD_NUM  17
#define MAX_RESULT 100
struct Args {
    std::string tel;
    std::string ip;
    std::string cid;
    std::string f_date;
    std::string t_date;
    std::string user;
    std::string pass;
};
class Ipdr_log {
    private:
        Args in_args;
        bool args_ok;
        std::string path;
        std::string day_dir;
        std::vector< std::string> files;
        std::vector< 
            std::shared_ptr< std::vector<std::string> > > result;
    public:
        Ipdr_log():in_args{},args_ok{false}{}
        bool getArgs(const std::string args);
        std::string getUser(){ return args_ok? in_args.user: ""; }
        std::string getPass(){ return args_ok? in_args.pass: ""; }
        bool search(std::string /*path*/);
        bool files_list();
        bool search_file(std::string /*file_in_tmp*/);
        bool gunzip_to_tmp(std::string /*file_pattern*/);
        size_t files_count() { return files.size(); }
        std::shared_ptr< std::vector<std::string> > 
            get_file_list(std::string /*path*/);
        std::string getResults();
        ~Ipdr_log(){}
};
