#ifndef _CRYPTL_AES_HPP_
#define _CRYPTL_AES_HPP_

#include <array>

#include <cryptl/AES_Cipher.hpp>
#include <cryptl/AES_InvCipher.hpp>
#include <cryptl/BitwiseINT.hpp>

namespace cryptl {

////////////////////////////////////////////////////////////////////////////////
// AES variants
//

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_All
{
public:
    AES_All() = default;

    static bool isEncryption() { return true; }
    static bool isDecryption() { return false; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_All
{
public:
    UNAES_All() = default;

    static bool isEncryption() { return false; }
    static bool isDecryption() { return true; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_128
{
public:
    AES_128() = default;

    static bool isEncryption() { return true; }
    static bool isDecryption() { return false; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key128Type KeyType;
    typedef typename KeyExpansion::Schedule128Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_128
{
public:
    UNAES_128() = default;

    static bool isEncryption() { return false; }
    static bool isDecryption() { return true; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key128Type KeyType;
    typedef typename KeyExpansion::Schedule128Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_192
{
public:
    AES_192() = default;

    static bool isEncryption() { return true; }
    static bool isDecryption() { return false; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key192Type KeyType;
    typedef typename KeyExpansion::Schedule192Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_192
{
public:
    UNAES_192() = default;

    static bool isEncryption() { return false; }
    static bool isDecryption() { return true; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key192Type KeyType;
    typedef typename KeyExpansion::Schedule192Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_256
{
public:
    AES_256() = default;

    static bool isEncryption() { return true; }
    static bool isDecryption() { return false; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key256Type KeyType;
    typedef typename KeyExpansion::Schedule256Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_256
{
public:
    UNAES_256() = default;

    static bool isEncryption() { return false; }
    static bool isDecryption() { return true; }

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key256Type KeyType;
    typedef typename KeyExpansion::Schedule256Type ScheduleType;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

typedef AES_All<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    AES;

typedef UNAES_All<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    UNAES;

typedef AES_128<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    AES128;

typedef UNAES_128<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    UNAES128;

typedef AES_192<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    AES192;

typedef UNAES_192<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    UNAES192;

typedef AES_256<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    AES256;

typedef UNAES_256<
    std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
    UNAES256;

} // namespace cryptl

#endif
