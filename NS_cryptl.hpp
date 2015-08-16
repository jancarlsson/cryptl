#ifndef _CRYPTL_NS_CRYPTL_HPP_
#define _CRYPTL_NS_CRYPTL_HPP_

#include <array>
#include <cstdint>
#include <istream>

#include <cryptl/Bless.hpp>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// namespace as type for algorithm template parameter
//

class NS
{
public:
    // bless
    template <typename T>
    static bool bless(T& x, std::istream& is) {
        return cryptl::bless(x, is);
    }

    // array comparison (imperative)
    template <std::size_t N>
    static bool notequal(const std::array<std::uint8_t, N>& x,
                         const std::array<std::uint8_t, N>& y) {
        for (std::size_t i = 0; i < N; ++i) {
            if (x[i] != y[i]) return true;
        }

        return false;
    }

    template <std::size_t N>
    static bool notequal(const std::array<std::uint32_t, N>& x,
                         const std::array<std::uint32_t, N>& y) {
        for (std::size_t i = 0; i < N; ++i) {
            if (x[i] != y[i]) return true;
        }

        return false;
    }

    template <std::size_t N>
    static bool notequal(const std::array<std::uint64_t, N>& x,
                         const std::array<std::uint64_t, N>& y) {
        for (std::size_t i = 0; i < N; ++i) {
            if (x[i] != y[i]) return true;
        }

        return false;
    }
};

} // namespace cryptl

#endif
