#include <exception>
#include <iostream>

class Log  {
    public:
        static const int LEVEL = 5;
        static void log(int level, std::string msg){
            if(level < LEVEL)
                std::clog << msg << "\n";
        }
};
class Error_socket: public std::exception {
    std::string msg;
    public:
        Error_socket(std::string _msg):msg{_msg}{
            Log::log(1, "Exception in socket: " +  _msg);
        }
        virtual const char*  what() const throw(){
            return msg.c_str();
        }
};
class Error_log: public std::exception {
    std::string msg;
    public:
        Error_log(std::string _msg):msg{_msg}{
            Log::log(1, "Exception in Log: " +  _msg);
        }
        virtual const char*  what() const throw(){
            return msg.c_str();
        }
};
