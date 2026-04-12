#include "dynamic_loader.hpp"

#include <fstream>

using namespace std;
using namespace tbd;

int main()
{
    {
        dynamic_loader libm("libm.so.6");
        double x = 2.0, y = 3.0;
        printf("pow %f of %f is %f\n", x, y, libm["pow"].call<double>(x, y));
    }

    {
        static constexpr size_t bufsz = 4096;
        uint8_t buf[bufsz] = {0};
        ifstream ifs("/dev/urandom");
        ifs.read((char*)buf, bufsz);
        dynamic_loader libz("libz.so.1");
        printf("crc32 = %lu\n", libz["crc32"].call<unsigned long>(0, buf, bufsz));
    }

    return 0;
}
