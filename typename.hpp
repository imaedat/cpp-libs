#ifndef TYPENAME_HPP_
#define TYPENAME_HPP_

#include <cxxabi.h>

#include <string>
#include <typeinfo>

std::string typename_(const char *mangled)
{
    int status;
    char *n = abi::__cxa_demangle(mangled, 0, 0, &status);
    std::string name(n);
    free(n);
    return name;
}

#define TYPENAME(obj) typename_(typeid((obj)).name())

#endif
