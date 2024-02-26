#include <iostream>
#include <fstream>

class Ini_file {
    private:
        std::string path;
        std::ifstream ini;
    public:
        Ini_file(const std::string _path):path{_path}{
            ini.open(path, std::ios::in);
        }
        bool isOk(){ return ini.is_open(); }
        bool auth(const std::string ,const std::string pass);
        std::string logPath();
        ~Ini_file(){
            ini.close();
        }
};
