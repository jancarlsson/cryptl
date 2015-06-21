#ifndef _CRYPTL_BLESS_HPP_
#define _CRYPTL_BLESS_HPP_

#include <array>
#include <climits>
#include <cstdint>
#include <istream>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// blessing (initialize variables)
//

// 8/32/64-bit values from input stream
template <typename T>
bool bless(T& a, std::istream& is) {
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

// array from input stream
template <typename T, std::size_t N>
bool bless(std::array<T, N>& a, std::istream& is) {
    for (auto& x : a) {
        if (! bless(x, is)) return false;
    }

    return true;
}

} // namespace cryptl

#endif
