#include "popen.hpp"

#include <unistd.h>

int main()
{
    tbd::popen proc("ls -l /proc/", getpid(), "/fd/");
    while (auto line = proc.getline()) {
        puts(line->c_str());
    }
}
