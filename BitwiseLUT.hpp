#ifndef _CRYPTL_BITWISE_LUT_HPP_
#define _CRYPTL_BITWISE_LUT_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// lookup table for unsigned integer types
//

template <typename T, typename U, typename VAL, typename BITWISE>
class BitwiseLUT
{
public:
    template <std::size_t N>
    BitwiseLUT(const std::array<VAL, N>& table_elements)
        : m_value(table_elements.begin(),
                  table_elements.end())
    {
#ifdef USE_ASSERT
        // empty look up table does not make sense
        assert(N > 0);
#endif
    }

    std::size_t size() const { return m_value.size(); }

    U operator[] (const T& x) const
    {
        const auto N = m_value.size();

        if (1 == N) {
            // returns value if index is 0, else all clear bits
            return
                BITWISE::AND(
                    BITWISE::_constant(m_value[0]),
                    BITWISE::_CMPLMNT(BITWISE::_bitmask(0 != x)));

        } else {
            auto sum =
                BITWISE::_AND(
                    BITWISE::_constant(m_value[0]),
                    BITWISE::_CMPLMNT(BITWISE::_bitmask(0 != x)));

            for (std::size_t i = 1; i < N - 1; ++i) {
                sum =
                    BITWISE::_ADDMOD(
                        sum,
                        BITWISE::_AND(
                            BITWISE::_constant(m_value[i]),
                            BITWISE::_CMPLMNT(BITWISE::_bitmask(i != x))));
            }

            return
                BITWISE::ADDMOD(
                    sum,
                    BITWISE::_AND(
                        BITWISE::_constant(m_value[N - 1]),
                        BITWISE::_CMPLMNT(BITWISE::_bitmask((N-1) != x))));
        }
    }

private:
    const std::vector<VAL> m_value;
};

} // namespace cryptl

#endif
