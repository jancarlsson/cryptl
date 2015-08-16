#ifndef _CRYPTL_ASCII_HEX_HPP_
#define _CRYPTL_ASCII_HEX_HPP_

#include <array>
#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include <cryptl/DataPusher.hpp>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// convert hexadecimal ASCII to binary
//

template <typename T>
T asciiHexToNibble(const char c) {
    switch (c) {
    case ('0') : return 0;
    case ('1') : return 1;
    case ('2') : return 2;
    case ('3') : return 3;
    case ('4') : return 4;
    case ('5') : return 5;
    case ('6') : return 6;
    case ('7') : return 7;
    case ('8') : return 8;
    case ('9') : return 9;

    case ('a') :
    case ('A') :
        return 10;

    case ('b') :
    case ('B') :
        return 11;

    case ('c') :
    case ('C') :
        return 12;

    case ('d') :
    case ('D') :
        return 13;

    case ('e') :
    case ('E') :
        return 14;

    case ('f') :
    case ('F') :
        return 15;
    }

    return -1;
}

template <typename T>
T asciiHexToOctet(const char high, const char low, bool& status) {
    const T
        highNibble = asciiHexToNibble<T>(high),
        lowNibble = asciiHexToNibble<T>(low);

    if (-1 == highNibble || -1 == lowNibble)
        status = false;

    return (highNibble << 4) | lowNibble;
}

template <typename T>
bool asciiHexToVector(const std::string& hexDigits, std::vector<T>& v) {
    const std::size_t
        N = hexDigits.size(),
        numDigits = 2 * sizeof(T),
        numBits = 8 * sizeof(T);

    // insist on even number of fully specified elements
    if (0 != N % numDigits) return false;

    bool status = true;

    for (std::size_t i = 0; i < N; i += numDigits) {
        T e = 0;

        for (std::size_t j = 0; j < numDigits; j += 2) {
            // assume big-endian format of hex digits in text string
            // most significant digit is first on the left
            // least significant digit is last on the right
            const T b =
                asciiHexToOctet<T>(
                    hexDigits[i + j],
                    hexDigits[i + j + 1],
                    status);

            e |= (b << (numBits - 8 - 4*j));
        }

        v.push_back(e);
    }

    return status;
}

template <typename T, std::size_t N>
bool asciiHexToArray(const std::string& hexDigits, std::array<T, N>& a) {
    std::vector<T> v;

    if (!asciiHexToVector(hexDigits, v) || N != v.size()) {
        return false;

    } else {
        for (std::size_t i = 0; i < N; ++i)
            a[i] = v[i];

        return true;
    }
}

////////////////////////////////////////////////////////////////////////////////
// convert binary to hexadecimal ASCII
//

template <bool TRAILING_SPACE>
class PrintHex
{
public:
    PrintHex(std::ostream& os)
        : m_nibbles{'0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
          m_os(os)
    {}

    void pushOctet(const std::uint8_t a) {
        m_os << m_nibbles[a >> CHAR_BIT / 2]
             << m_nibbles[a & 0xf];

        if (TRAILING_SPACE) m_os << ' ';
    }

private:
    const std::array<char, 16> m_nibbles;
    std::ostream& m_os;
};

template <typename T, std::size_t N>
std::string asciiHex(const std::array<T, N>& a, const bool space = false) {
    std::stringstream ss;
    DataPusher<PrintHex<false>> hexpr(ss);

    hexpr.push(a[0]);
    for (std::size_t i = 1; i < N; ++i) {
        if (space) ss << " ";
        hexpr.push(a[i]);
    }

    return ss.str();
}

template <typename T>
std::string asciiHex(const std::vector<T>& a, const bool space = false) {
    if (a.empty()) return std::string();

    std::stringstream ss;
    DataPusher<PrintHex<false>> hexpr(ss);

    hexpr.push(a[0]);
    for (std::size_t i = 1; i < a.size(); ++i) {
        if (space) ss << " ";
        hexpr.push(a[i]);
    }

    return ss.str();
}

} // namespace cryptl

#endif
