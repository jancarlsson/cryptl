#ifndef _CRYPTL_CIPHER_MODES_HPP_
#define _CRYPTL_CIPHER_MODES_HPP_

#include <cassert>
#include <cstdint>
#include <vector>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// block cipher modes
//

// electronic code book mode (ECB)
template <typename T, typename U>
std::vector<U> ECB(T dummy,
                   const typename T::KeyType& key,
                   const std::vector<U>& inText)
{
    typename T::ScheduleType scheduleBlock;
    typename T::KeyExpansion keyExpand;
    keyExpand(key, scheduleBlock);

    typename T::BlockType inBlock, outBlock;
    const std::size_t B = inBlock.size();
    const std::size_t N = inText.size() / B;
#ifdef USE_ASSERT
    // even number of blocks
    assert(N * B == inText.size());
#endif
    std::vector<U> outText(inText.size());

    typename T::Algo algo;
    for (std::size_t i = 0; i < N; ++i) {
        const std::size_t offset = i * B;

        for (std::size_t j = 0; j < B; ++j)
            inBlock[j] = inText[j + offset];

        algo(inBlock, outBlock, scheduleBlock);

        for (std::size_t j = 0; j < B; ++j)
            outText[j + offset] = outBlock[j];
    }

    return outText;
}

// cipher block chaining mode (CBC)
template <typename T, typename U>
std::vector<U> CBC(T dummy,
                   const typename T::KeyType& key,
                   const typename T::BlockType& IV,
                   const std::vector<U>& inText)
{
    typename T::ScheduleType scheduleBlock;
    typename T::KeyExpansion keyExpand;
    keyExpand(key, scheduleBlock);

    typename T::BlockType inBlock, outBlock, lastBlock = IV;
    const std::size_t B = inBlock.size();
    const std::size_t N = inText.size() / B;
#ifdef USE_ASSERT
    // even number of blocks
    assert(N * B == inText.size());
#endif
    std::vector<U> outText(inText.size());

    typename T::Algo algo;
    for (std::size_t i = 0; i < N; ++i) {
        const std::size_t offset = i * B;

        if (T::isEncryption()) {
            for (std::size_t j = 0; j < B; ++j)
                inBlock[j] = inText[j + offset] ^ lastBlock[j];

            algo(inBlock, outBlock, scheduleBlock);

            for (std::size_t j = 0; j < B; ++j)
                outText[j + offset] = outBlock[j];

            lastBlock = outBlock;

        } else { // isDecryption
            for (std::size_t j = 0; j < B; ++j)
                inBlock[j] = inText[j + offset];

            algo(inBlock, outBlock, scheduleBlock);

            for (std::size_t j = 0; j < B; ++j)
                outText[j + offset] = outBlock[j] ^ lastBlock[j];

            lastBlock = inBlock;
        }
    }

    return outText;
}

// output feedback mode (OFB)
template <typename T, typename U>
std::vector<U> OFB(T dummy,
                   const typename T::KeyType& key,
                   const typename T::BlockType& IV,
                   const std::vector<U>& inText)
{
    typename T::ScheduleType scheduleBlock;
    typename T::KeyExpansion keyExpand;
    keyExpand(key, scheduleBlock);

    typename T::BlockType inBlock = IV, outBlock;
    const std::size_t B = inBlock.size();
    const std::size_t N = inText.size() / B;
#ifdef USE_ASSERT
    // even number of blocks
    assert(N * B == inText.size());
#endif
    std::vector<U> outText(inText.size());

    typename T::Algo algo;
    for (std::size_t i = 0; i < N; ++i) {
        const std::size_t offset = i * B;

        algo(inBlock, outBlock, scheduleBlock);
        inBlock = outBlock;

        for (std::size_t j = 0; j < B; ++j)
            outText[j + offset] = outBlock[j] ^ inText[j + offset];
    }

    return outText;
}

// cipher feedback mode (CFB)
template <typename T, typename U>
std::vector<U> CFB(T dummy,
                   const typename T::KeyType& key,
                   const typename T::BlockType& IV,
                   const std::vector<U>& inText)
{
    typename T::ScheduleType scheduleBlock;
    typename T::KeyExpansion keyExpand;
    keyExpand(key, scheduleBlock);

    typename T::BlockType inBlock, outBlock, lastBlock = IV;
    const std::size_t B = inBlock.size();
    const std::size_t N = inText.size() / B;
#ifdef USE_ASSERT
    // even number of blocks
    assert(N * B == inText.size());
#endif
    std::vector<U> outText(inText.size());

    typename T::Algo algo;
    for (std::size_t i = 0; i < N; ++i) {
        const std::size_t offset = i * B;

        inBlock = lastBlock;
        algo(inBlock, outBlock, scheduleBlock);
        lastBlock = T::isEncryption() ? outBlock : inBlock;

        for (std::size_t j = 0; j < B; ++j)
            outText[j + offset] = outBlock[j] ^ inText[j + offset];
    }

    return outText;
}

} // namespace cryptl

#endif
