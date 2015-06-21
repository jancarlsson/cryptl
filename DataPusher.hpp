#ifndef _CRYPTL_DATA_PUSHER_HPP_
#define _CRYPTL_DATA_PUSHER_HPP_

#include <array>
#include <climits>
#include <cstdint>
#include <istream>
#include <memory>
#include <string>
#include <vector>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// data pusher
//

template <typename T>
class DataPusher
{
public:
    DataPusher() = default;

    template <typename X>
    DataPusher(X& a) // not const reference for std::ostream
        : m_buf(a)
    {}

    T& operator* () {
        return m_buf;
    }

    const T* operator-> () const {
        return std::addressof(m_buf);
    }

    // 8-bit
    void push8(const std::uint8_t a) {
        m_buf.pushOctet(a);
    }

    // 32-bit
    void push32(const std::uint32_t a) {
        push8(a >> 3 * CHAR_BIT);
        push8((a >> 2 * CHAR_BIT) & 0xff);
        push8((a >> CHAR_BIT) & 0xff);
        push8(a & 0xff);
    }

    // 64-bit
    void push64(const std::uint64_t a) {
        push32(a >> 4 * CHAR_BIT);
        push32(a & 0xffffffff);
    }

    // string
    void pushText(const std::string& a) {
        for (const auto& c : a) push8(c);
    }

    void push(const std::uint8_t a) { push8(a); }
    void push(const std::uint32_t a) { push32(a); }
    void push(const std::uint64_t a) { push64(a); }
    void push(const std::string& a) { pushText(a); }
    void push(const char* a) { push(std::string(a)); }

    template <typename U, std::size_t N>
    void push(const std::array<U, N>& a) {
        for (const auto& b : a) push(b);
    }

    template <typename U>
    void push(const std::vector<U>& a) {
        for (const auto& b : a) push(b);
    }

    void push(const DataPusher& other) {
        for (const auto& a : other->data()) push8(a);
    }

private:
    T m_buf;
};

} // namespace cryptl

#endif
