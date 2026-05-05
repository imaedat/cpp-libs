#ifndef TYPENAME_HPP_
#define TYPENAME_HPP_

#include <cxxabi.h>

#include <cstdlib>
#include <string>
#include <typeinfo>

namespace tbd {
inline std::string demangle(const char* mangled)
{
    int status;
    char* n = abi::__cxa_demangle(mangled, 0, 0, &status);
    std::string name(n);
    std::free(n);
    return name;
}
}  // namespace tbd

#define TYPENAME(obj) tbd::demangle(typeid((obj)).name())

#endif
