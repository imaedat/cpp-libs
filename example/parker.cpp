#include "parker.hpp"

#include <unistd.h>

#include <thread>

using namespace tbd;

int main()
{
    srandom(time(nullptr));

    parker p;

    std::thread th([&] {
        puts("2. thread : before unpark");
        usleep(random() % (1000 * 1000));
        p.unpark();
        puts("3. thread : after unpark");
    });

    puts("1. main   : before park");
    p.park();
    puts("4. main   : after park");

    th.join();
}
