#include "cmdopt.hpp"

#include <iostream>

using namespace tbd;
using namespace std;

int main(int argc, char* argv[])
{
    cmdopt opt(argv[0]);
    opt.optional('a', "addr", "127.0.0.1", "broker address");
    opt.optional('p', "port", 55555, "broker port");
    opt.mandatory('t', "", "topic to publish");
    opt.optional('\0', "message", "", "message to publish");
    opt.flag('h', "help", "show this message");
    opt.flag('v', "version", "show version");

    puts("---");
    std::cout << opt.usage();
    puts("---");
    opt.parse(argc, argv);

    cout << "addr\t" << opt.get<std::string>('a') << "\n";
    cout << "port\t" << opt.get<uint16_t>('p') << "\n";
    cout << "topic\t" << opt.get<std::string>('t') << "\n";
    cout << "message\t" << opt.get<std::string>("message") << "\n";
    cout << "help\t" << boolalpha << opt.exists('h') << "\n";
    cout << "version\t" << boolalpha << opt.exists('v') << "\n";

    puts("---");
    cout << "plain args:";
    for (const auto& a : opt.rest_args()) {
        cout << " " << a;
    }
    cout << endl;
}
