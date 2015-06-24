#ifndef _CRYPTL_DIGEST_HPP_
#define _CRYPTL_DIGEST_HPP_

#include <climits>
#include <cstdint>
#include <functional>
#include <istream>
#include <sstream>
#include <vector>

#include <cryptl/Bless.hpp>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// convenient SHA message digest for data
//

// consumes the entire stream which is presumed to be properly padded
template <typename T>
typename T::DigType digest(
    T hashAlgo,
    std::istream& is,
    std::function<bool (typename T::WordType&, std::istream&)> func)
{
    typename T::MsgType msg;

    while (!is.eof() && bless(msg, is, func)) {
        hashAlgo.msgInput(msg);
    }

    hashAlgo.computeHash();
    return hashAlgo.digest();
}

template <typename T>
typename T::DigType digest(T hashAlgo, std::istream& is)
{
    return digest(
        hashAlgo,
        is,
        [] (typename T::WordType& a, std::istream& is) {
            return bless(a, is);
        });
}

// pads the byte vector message
template <typename T>
typename T::DigType digest(T hashAlgo, const std::vector<std::uint8_t>& a)
{
    std::stringstream ss;
    for (const auto& b : a) ss.put(b);

    std::size_t lengthBits = a.size() * CHAR_BIT;
    T::padMessage(ss, lengthBits);

    return digest(
        hashAlgo,
        ss,
        [] (typename T::WordType& a, std::istream& is) {
            return bless(a, is);
        });
}

} // namespace cryptl

#endif
