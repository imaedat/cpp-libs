#include "logger.hpp"

#include <stdlib.h>
#include <unistd.h>

#include <sstream>
#include <string>

using namespace std;
using namespace std::string_literals;
using namespace tbd;

namespace {
template <typename T>
string to_string(const T& value)
{
    if constexpr (is_convertible_v<T, string_view>) {
        return string(string_view(value));
    } else if constexpr (is_arithmetic_v<T>) {
        return std::to_string(value);
    }

    static_assert(is_convertible_v<T, string_view> || is_arithmetic_v<T>,
                  "Unsupported type for string concatenation");
    return "";
}

template <typename... Args>
void command(const Args&... args)
{
    string cmd;
    cmd.reserve(128);
    (cmd += ... += to_string(args));
    printf("$ %s\n", cmd.c_str());
    [[maybe_unused]] int ret = system(cmd.c_str());
}
}  // namespace

int main()
{
    srandom(time(nullptr));
    char name[32] = {0};
    auto rand = 1 + random() % 10000;
#if 1
    sprintf(name, "test-%ld.log", rand);
#else
    sprintf(name, "/dev/stdout");
#endif
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

    puts("---");
    command("cat ", name);

    puts("---");
    command("mv ", name, " ", name + ".bak"s);
    puts("# reopen and write");

    logger.info("before reopen");
    logger.reopen();
    logger.info("after reopen");
    logger.flush();

    command("ls -li ", name + "*"s);
    command("cat ", name);

    puts("---");
    puts("# rotate and write");
    logger.rotate();
    logger.info("after rotate");
    logger.flush();

    command("ls -li ", name + "*"s);
    command("cat ", name);

    puts("---");
    command("rm -fv ", name + "*"s);
}
