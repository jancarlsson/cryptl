#ifndef _CRYPTL_DIGEST_HPP_
#define _CRYPTL_DIGEST_HPP_

#include <climits>
#include <cstdint>
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
typename T::DigType digest(T hashAlgo, std::istream& is) {
    typename T::MsgType msg;

    while (!is.eof() && bless(msg, is)) {
        hashAlgo.msgInput(msg);
    }

    hashAlgo.computeHash();
    return hashAlgo.digest();
}

// pads the byte vector message
template <typename T>
typename T::DigType digest(T hashAlgo, const std::vector<std::uint8_t>& a) {
    std::stringstream ss;
    for (const auto& b : a) ss.put(b);

    std::size_t lengthBits = a.size() * CHAR_BIT;
    T::padMessage(ss, lengthBits);

    return digest(hashAlgo, ss);
}

} // namespace cryptl

#endif
