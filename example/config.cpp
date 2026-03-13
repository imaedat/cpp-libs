#include "config.hpp"

#include <stdlib.h>

#include <filesystem>
#include <fstream>
#include <iostream>

using namespace tbd;
using namespace std;

#define CONFIG_FILE "config.env"

void gen_config()
{
    ofstream ofs(CONFIG_FILE);

    ofs << std::string(
               R"(# comment
BOOL_VAL = true           # comment
INT_VAL  = 42             # old value 41
HEX_VAL  = 0x1000
STR_VAL  = "hello, world" # HELLO
)") << flush;

    puts("--- config file ---");
    [[maybe_unused]] int ret = system("cat " CONFIG_FILE);
    puts("-------------------\n");
}

int main()
{
    gen_config();

    config c(CONFIG_FILE);
    [[maybe_unused]] int ret = system("rm -f " CONFIG_FILE);
    cout << "BOOL_VAL to bool   : " << boolalpha << c.get<bool>("BOOL_VAL") << endl;
    cout << "BOOL_VAL to int    : " << boolalpha << c.get<int>("BOOL_VAL") << endl;
    cout << "\n";
    cout << "INT_VAL  to int    : " << c.get<int>("INT_VAL") << endl;
    cout << "INT_VAL  to bool   : " << c.get<bool>("INT_VAL") << endl;
    cout << "\n";
    cout << "HEX_VAL  to int    : " << c.get<int>("HEX_VAL") << endl;
    cout << "HEX_VAL  to bool   : " << c.get<bool>("HEX_VAL") << endl;
    cout << "\n";
    cout << "STR_VAL  to string : " << c.get<string>("STR_VAL") << endl;
    cout << "STR_VAL  to bool   : " << boolalpha << c.get<bool>("STR_VAL") << endl;
    cout << "STR_VAL  to int    : " << c.get<int>("STR_VAL") << endl;
}
