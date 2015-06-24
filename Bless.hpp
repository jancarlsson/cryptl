#ifndef _CRYPTL_BLESS_HPP_
#define _CRYPTL_BLESS_HPP_

#include <array>
#include <climits>
#include <cstdint>
#include <functional>
#include <istream>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// blessing (initialize variables)
//

template <typename T>
bool bless_internal(T& a, std::istream& is) {
    a = 0;

    char c;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        if (is.eof() || !is.get(c))
            return false;
        else
            a = (a << CHAR_BIT) | static_cast<std::uint8_t>(c);
    }

    return true;
}

// 8-bit values from input stream
template <typename T>
bool bless(std::uint8_t& a, T& is) {
    return bless_internal(a, is);
}

// 32-bit values from input stream
template <typename T>
bool bless(std::uint32_t& a, T& is) {
    return bless_internal(a, is);
}

// 64-bit values from input stream
template <typename T>
bool bless(std::uint64_t& a, T& is) {
    return bless_internal(a, is);
}

// array from input stream
template <typename T, std::size_t N>
bool bless(std::array<T, N>& a,
           std::istream& is,
           std::function<bool (T&, std::istream&)> func)
{
    for (auto& x : a) {
        if (! func(x, is)) return false;
    }

    return true;
}

} // namespace cryptl

#endif
