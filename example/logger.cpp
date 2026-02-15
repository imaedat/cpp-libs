#include "logger.hpp"

#include <stdlib.h>
#include <unistd.h>

#include <sstream>
#include <string>

using namespace std;
using namespace std::string_literals;
using namespace tbd;

int main()
{
    srandom(time(nullptr));
    char name[32] = {0};
    auto rand = 1 + random() % 10000;
    sprintf(name, "test-%ld.log", rand);
    logger logger("dummy", name);
    logger.set_level("debug");

    logger.info("hello from %s", "main thread");
    auto thr = thread([&] {
        logger.trace("this is trace message");
        logger.debug("this is debug message");
        logger.error("this is %ld times emergency message!", rand);
    });
    thr.join();

    // const string&
    string s1("s1");
    logger.info("%s", s1);

    // string&&
    logger.info("%s", "s2"s);

    // string_view
    string_view s3("s3");
    logger.info("%s", s3);

    // string_view&&
    logger.info("%s", string_view("s4"));

    // const char *
    logger.info("%s", "s5");

    // char *
    char s6[] = {'s', '6', '\0'};
    logger.info("%s", s6);

    logger.flush();

    ostringstream ss;
    ss << "cat " << name;
    printf("$ %s\n", ss.str().c_str());
    system(ss.str().c_str());

    logger.rotate();

    ss.str("");
    ss << "ls -li " << name << "*";
    printf("$ %s\n", ss.str().c_str());
    system(ss.str().c_str());

    ss.str("");
    ss << "rm " << name << "*";
    system(ss.str().c_str());
}
