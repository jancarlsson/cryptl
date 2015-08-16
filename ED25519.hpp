#ifndef _CRYPTL_ED25519_HPP_
#define _CRYPTL_ED25519_HPP_

#include <array>
#include <cstdint>
#include <sstream>
#include <vector>

#include <cryptl/BitwiseINT.hpp>
#include <cryptl/ED25519_ge.hpp>
#include <cryptl/ED25519_sc.hpp>
#include <cryptl/NS_cryptl.hpp>
#include <cryptl/SHA_512.hpp>

namespace cryptl {

// direct translation of: supercop-20141124/crypto_sign/ed25519/ref/keypair.c
// direct translation of: supercop-20141124/crypto_sign/ed25519/ref/open.c
// direct translation of: supercop-20141124/crypto_sign/ed25519/ref/sign.c

////////////////////////////////////////////////////////////////////////////////
// public and secret key pair
//

template <typename B,     // bool variable
          typename U8,    // 8-bit variable
          typename U32,   // 32-bit variable
          typename U64,   // 64-bit variable
          typename BIT8,  // Bitwise for 8-bit
          typename BIT32, // Bitwise for 32-bit
          typename BIT64, // Bitwise for 64-bit
          typename MSG,   // 64-bit variable for hash pre-image
          typename FUN,   // SHA functions
          typename NS>    // namespace type
class ED_25519
{
    typedef sc25519<U32, U8, B, BIT32, BIT8, NS> SC;
    typedef ge25519<U32, U8, B, BIT32, BIT8, NS> GE;

public:
    // public key from 32 byte secret
    static
    void keypair(std::array<U8, 32>& pk,
                 const std::array<U8, 32>& sk)
    {
        std::array<U8, 32> az;
        init_az(az, sk);

        SC scsk;
        scsk.from32bytes(az);

        GE gepk;
        gepk.scalarmult_base(scsk);
        gepk.pack(pk);
    }

    // sign message
    static
    void sign(std::array<U8, 32>& R,
              std::array<U8, 32>& S,
              const std::vector<U8>& m,
              const std::array<U8, 32>& pk,
              const std::array<U8, 32>& sk)
    {
        std::array<U8, 64> az;
        init_az(az, sk);
        // az: 32-byte scalar a, 32-byte randomizer z

        std::vector<U8> vnonce(64), vzm(32 + m.size());
        for (std::size_t i = 0; i < 32; ++i) vzm[i] = az[i + 32];
        for (std::size_t i = 0; i < m.size(); ++i) vzm[i + 32] = m[i];
        // vzm: 32-byte randomizer z, message m

        sha512(vnonce, vzm);
        std::array<U8, 64> nonce;
        for (std::size_t i = 0; i < 64; ++i) nonce[i] = vnonce[i];
        // nonce: 64-byte H(z, m)

        SC sck;
        sck.from64bytes(nonce);

        GE ger;
        ger.scalarmult_base(sck);
        ger.pack(R);

        std::vector<U8> vhram(64), vRAm(64 + m.size());
        for (std::size_t i = 0; i < 32; ++i) vRAm[i] = R[i];
        for (std::size_t i = 0; i < 32; ++i) vRAm[i + 32] = pk[i];
        for (std::size_t i = 0; i < m.size(); ++i) vRAm[i + 64] = m[i];
        // vRAm: 32-byte R, 32-byte A, message m

        sha512(vhram, vRAm);
        std::array<U8, 64> hram;
        for (std::size_t i = 0; i < 64; ++i) hram[i] = vhram[i];
        // hram: 64-byte H(R, A, m)

        SC scs, scsk;
        scs.from64bytes(hram);
        std::array<U8, 32> aza;
        for (std::size_t i = 0; i < 32; ++i) aza[i] = az[i];
        scsk.from32bytes(aza);
        scs.mul(scs, scsk);
        scs.add(scs, sck);
        // scs: S = nonce + H(R, A, m)a

        scs.to32bytes(S);
    }

    // verify signature
    static
    B open(const std::array<U8, 32>& R,
           const std::array<U8, 32>& S,
           const std::vector<U8>& m,
           const std::array<U8, 32>& pk)
    {
        GE get1;
        const B badsig =
            BIT8::logicalOR(
                BIT8::testbit(S[31], 7),
                BIT8::logicalOR(
                    BIT8::testbit(S[31], 6),
                    BIT8::logicalOR(
                        BIT8::testbit(S[31], 5),
                        BIT8::logicalNOT(get1.unpackneg_vartime(pk)))));

        SC scs;
        scs.from32bytes(S);

        std::vector<U8> vhram(64), vm(64 + m.size());
        for (std::size_t i = 0; i < 32; ++i) vm[i] = R[i];
        for (std::size_t i = 0; i < 32; ++i) vm[i + 32] = pk[i];
        for (std::size_t i = 0; i < m.size(); ++i) vm[i + 64] = m[i];
        // vm: 32-byte R, 32-byte A, message m

        sha512(vhram, vm);
        std::array<U8, 64> hram;
        for (std::size_t i = 0; i < 64; ++i) hram[i] = vhram[i];
        // hram: 64-byte H(R, A, m)

        SC schram;
        schram.from64bytes(hram);

        GE get2;
        get2.double_scalarmult_vartime(get1, schram, GE::base(), scs);

        std::array<U8, 32> rcheck;
        get2.pack(rcheck);

        return BIT32::logicalAND(
            BIT32::logicalNOT(badsig),
            BIT32::logicalNOT(NS::notequal(R, rcheck)));
    }

private:
    static
    void sha512(std::vector<U8>& out, const std::vector<U8>& msg) {
        const std::size_t
            num = msg.size() / 8,
            rem = msg.size() % 8;

        std::vector<U64> v(0 == rem ? num : num + 1);

        // whole words
        for (std::size_t i = 0; i < num; ++i) {
            const U8
                &u0 = msg[i * 8],
                &u1 = msg[i * 8 + 1],
                &u2 = msg[i * 8 + 2],
                &u3 = msg[i * 8 + 3],
                &u4 = msg[i * 8 + 4],
                &u5 = msg[i * 8 + 5],
                &u6 = msg[i * 8 + 6],
                &u7 = msg[i * 8 + 7];

            U64& w = v[i];

            w = BIT64::OR(BIT64::SHL(BIT8::xword(u0, w), 56),
                BIT64::OR(BIT64::SHL(BIT8::xword(u1, w), 48),
                BIT64::OR(BIT64::SHL(BIT8::xword(u2, w), 40),
                BIT64::OR(BIT64::SHL(BIT8::xword(u3, w), 32),
                BIT64::OR(BIT64::SHL(BIT8::xword(u4, w), 24),
                BIT64::OR(BIT64::SHL(BIT8::xword(u5, w), 16),
                BIT64::OR(BIT64::SHL(BIT8::xword(u6, w), 8),
                                     BIT8::xword(u7, w))))))));
        }

        // final partial word
        auto& w = v.back();
        const std::size_t M = num * 8;
        switch (rem) {
        case (0) :
            break;
        case (1) :
            w = BIT64::OR(BIT64::constant(0x0080000000000000),
                          BIT64::SHL(BIT8::xword(msg[M + 0], w), 56));
            break;
        case (2) :
            w = BIT64::OR(BIT64::constant(0x0000800000000000),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 0], w), 56),
                          BIT64::SHL(BIT8::xword(msg[M + 1], w), 48)));
            break;
        case (3) :
            w = BIT64::OR(BIT64::constant(0x0000008000000000),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 0], w), 56),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 1], w), 48),
                          BIT64::SHL(BIT8::xword(msg[M + 2], w), 40))));
            break;
        case (4) :
            w = BIT64::OR(BIT64::constant(0x0000000080000000),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 0], w), 56),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 1], w), 48),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 2], w), 40),
                          BIT64::SHL(BIT8::xword(msg[M + 3], w), 32)))));
            break;
        case (5) :
            w = BIT64::OR(BIT64::constant(0x0000000000800000),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 0], w), 56),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 1], w), 48),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 2], w), 40),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 3], w), 32),
                          BIT64::SHL(BIT8::xword(msg[M + 4], w), 24))))));
            break;
        case (6) :
            w = BIT64::OR(BIT64::constant(0x0000000000008000),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 0], w), 56),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 1], w), 48),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 2], w), 40),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 3], w), 32),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 4], w), 24),
                          BIT64::SHL(BIT8::xword(msg[M + 5], w), 16)))))));
            break;
        case (7) :
            w = BIT64::OR(BIT64::constant(0x0000000000000080),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 0], w), 56),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 1], w), 48),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 2], w), 40),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 3], w), 32),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 4], w), 24),
                BIT64::OR(BIT64::SHL(BIT8::xword(msg[M + 5], w), 16),
                          BIT64::SHL(BIT8::xword(msg[M + 6], w), 8))))))));
            break;
        }

        // SHA-512
        typedef SHA_512<U64, MSG, U8, FUN> H;
        H algo;

        for (const auto& w : v) algo.msgInput(w);

        // pad message to full block
        std::stringstream ss;
        const std::size_t msgLengthBits = msg.size() * 8;
        std::size_t lengthBits = v.size() * 64;
        algo.padMessage(ss, msgLengthBits, lengthBits);
        U64 u;
        while (!ss.eof() && NS::bless(u, ss)) algo.msgInput(u);

        // calculate message digest
        algo.computeHash();
        const auto& dig = algo.digest();

        // message digest as bytes
        for (std::size_t i = 0; i < out.size(); ++i) {
            const std::size_t
                idx = i / 8,
                rem = i % 8;

            out[i] = BIT64::xword(BIT64::SHR(dig[idx], 56 - rem*8), out[i]);
        }
    }

    template <std::size_t N>
    static
    void init_az(std::array<U8, N>& az, const std::array<U8, 32>& sk) {
        // SHA-512
        std::vector<U8> vaz(N), vsk(32);
        for (std::size_t i = 0; i < 32; ++i) vsk[i] = sk[i];
        sha512(vaz, vsk);

        // mask and set bits
        vaz[0] = BIT8::AND(vaz[0], BIT8::constant(248));
        vaz[31] = BIT8::AND(vaz[31], BIT8::constant(127));
        vaz[31] = BIT8::OR(vaz[31], BIT8::constant(64));

        for (std::size_t i = 0; i < N; ++i) az[i] = vaz[i];
    }
};
    
////////////////////////////////////////////////////////////////////////////////
// typedef
//

typedef ED_25519<bool,
                 std::uint8_t,
                 std::uint32_t,
                 std::uint64_t,
                 BitwiseINT<std::uint8_t>,
                 BitwiseINT<std::uint32_t>,
                 BitwiseINT<std::uint64_t>,
                 std::uint64_t,
                 SHA_Functions<std::uint64_t,
                               std::uint64_t,
                               BitwiseINT<std::uint64_t>>,
                 NS>
    ED25519;

} // namespace cryptl

#endif
