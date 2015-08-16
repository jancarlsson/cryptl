#ifndef _CRYPTL_ED25519_SC_HPP_
#define _CRYPTL_ED25519_SC_HPP_

#include <array>
#include <cstdint>

namespace cryptl {

// direct translation of: supercop-20141124/crypto_sign/ed25519/ref/sc25519.c

////////////////////////////////////////////////////////////////////////////////
// shortsc25519
//

// T is 32-bit, U is 8-bit, B is bool, F is Bitwise for 32-bit
template <typename T, typename U, typename B, typename F>
class shortsc25519
{
public:
    void from16bytes(const std::array<U, 16>& x) {
        for (std::size_t i = 0; i < 16; ++i) {
            // r->v[i] = x[i];
            m_v[i] = F::xword(x[i], m_v[i]);
        }
    }

    const T& operator[] (const std::size_t i) const {
        return m_v[i];
    }

private:
    std::array<T, 16> m_v;
};

////////////////////////////////////////////////////////////////////////////////
// sc25519
//

// T is 32-bit, U is 8-bit, B is bool,
// FT is Bitwise for 32-bit
// FU is Bitwise for 8-bit
// NS is namespace
template <typename T, typename U, typename B, typename FT, typename FU, typename NS> 
class sc25519
{
public:
    void from32bytes(const std::array<U, 32>& x) {
        // crypto_uint32 t[64];
        std::array<T, 64> t;

        // for(i=0;i<32;i++) t[i] = x[i];
        for (std::size_t i = 0; i < 32; ++i) t[i] = FU::xword(x[i], t[i]);

        // for(i=32;i<64;++i) t[i] = 0;
        for (std::size_t i = 32; i < 64; ++i) t[i] = FT::constant(0);

        // barrett_reduce(r, t);
        barrett_reduce(t);
    }

    void from64bytes(const std::array<U, 64>& x) {
        // crypto_uint32 t[64];
        std::array<T, 64> t;

        // for(i=0;i<64;i++) t[i] = x[i];
        for (std::size_t i = 0; i < 64; ++i) t[i] = FU::xword(x[i], t[i]);

        // barrett_reduce(r, t);
        barrett_reduce(t);
    }

    void from_shortsc(const shortsc25519<T, U, B, FT>& x) {
        for (std::size_t i = 0; i < 16; ++i) {
            // r->v[i] = x->v[i];
            m_v[i] = x[i];
        }

        for (std::size_t i = 0; i < 16; ++i) {
            // r->v[16+i] = 0;
            m_v[16 + i] = FT::constant(0);
        }
    }

    void to32bytes(std::array<U, 32>& r) {
        for (std::size_t i = 0; i < 32; ++i) {
            // r[i] = x->v[i];
            r[i] = FT::xword(m_v[i], r[i]);
        }
    }

    B iszero_vartime() {
        // same as supercop in circuit form except not equal test
        return FT::logicalNOT(
            NS::notequal(m_v, FT::zero(m_v))); // inequality test is imperative
    }

    B isshort_vartime() {
        std::array<T, 16> a;
        for (std::size_t i = 0; i < 16; ++i) a[i] = m_v[16 + i];

        // same as supercop in circuit form except not equal test
        return FT::logicalNOT(
            NS::notequal(a, FT::zero(a))); // inequality test is imperative
    }

// not implemented as EDSL does not have less/greater for uint types
// B lt_vartime(const sc25519& y) {
//   int i;
//   for(i=31;i>=0;i--)
//   {
//     if(x->v[i] < y->v[i]) return 1;
//     if(x->v[i] > y->v[i]) return 0;
//   }
//   return 0;
// }

    void add(const sc25519& x, const sc25519& y) {
        for (std::size_t i = 0; i < 32; ++i) {
            // r->v[i] = x->v[i] + y->v[i];
            m_v[i] = FT::ADDMOD(x.m_v[i], y.m_v[i]);
        }

        for (std::size_t i = 0; i < 31; ++i) {
            // carry = r->v[i] >> 8;
            // r->v[i+1] += carry;
            m_v[i + 1] = FT::ADDMOD(m_v[i + 1], FT::SHR(m_v[i], 8));

            // r->v[i] &= 0xff;
            m_v[i] = FT::AND(m_v[i], FT::constant(0xff));
        }

        // reduce_add_sub(r);
        reduce_add_sub();
    }

    void sub_nored(const sc25519& x, const sc25519& y) {
        // crypto_uint32 b = 0;
        // crypto_uint32 t;
        T b = FT::constant(0), t;

        for (std::size_t i = 0; i < 32; ++i) {
            // t = x->v[i] - y->v[i] - b;
            t = FT::ADDMOD(x.m_v[i],
                           FT::ADDMOD(FT::negate(y.m_v[i]),
                                      FT::negate(b)));

            // r->v[i] = t & 255;
            m_v[i] = FT::AND(t, FT::constant(255));

            // b = (t >> 8) & 1;
            b = FT::AND(FT::SHR(t, 8), FT::constant(1));
        }
    }

    void mul(const sc25519& x, const sc25519& y) {
        // crypto_uint32 t[64];
        // for(i=0;i<64;i++)t[i] = 0;
        std::array<T, 64> t = FT::zero(t);

        for (std::size_t i = 0; i < 32; ++i) {
            for (std::size_t j = 0; j < 32; ++j) {
                // t[i+j] += x->v[i] * y->v[j];
                t[i + j] = FT::ADDMOD(t[i + j],
                                      FT::MULMOD(x.m_v[i], y.m_v[j]));
            }
        }
        
        // Reduce coefficients
        for (std::size_t i = 0; i < 63; ++i) {
            // carry = t[i] >> 8;
            // t[i+1] += carry;
            t[i + 1] = FT::ADDMOD(t[i + 1], FT::SHR(t[i], 8));

            // t[i] &= 0xff;
            t[i] = FT::AND(t[i], FT::constant(0xff));
        }

        // barrett_reduce(r, t);
        barrett_reduce(t);
    }

    void mul_shortsc(const sc25519& x, const shortsc25519<T, U, B, FT>& y) {
        // sc25519 t;
        sc25519 t;

        // sc25519_from_shortsc(&t, y);
        t.from_shortsc(y);

        // sc25519_mul(r, x, &t);
        mul(x, t);
    }

    void window3(std::array<U, 85>& r) {
        std::size_t i;

        for (i = 0; i < 10; ++i) {
            // r[8*i+0]  =  s->v[3*i+0]       & 7;
            r[8*i + 0] = FT::xword(
                FT::AND(m_v[3*i + 0], FT::constant(7)),
                r[8*i + 0]);

            // r[8*i+1]  = (s->v[3*i+0] >> 3) & 7;
            r[8*i + 1] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 0], 3), FT::constant(7)),
                r[8*i + 1]);

            // r[8*i+2]  = (s->v[3*i+0] >> 6) & 7;
            r[8*i + 2] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 0], 6), FT::constant(7)),
                r[8*i + 2]);

            // r[8*i+2] ^= (s->v[3*i+1] << 2) & 7;
            r[8*i + 2] = FU::XOR(
                r[8*i + 2],
                FT::xword(
                    FT::AND(FT::SHL(m_v[3*i + 1], 2), FT::constant(7)),
                    r[8*i + 2]));

            // r[8*i+3]  = (s->v[3*i+1] >> 1) & 7;
            r[8*i + 3] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 1], 1), FT::constant(7)),
                r[8*i + 3]);

            // r[8*i+4]  = (s->v[3*i+1] >> 4) & 7;
            r[8*i + 4] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 1], 4), FT::constant(7)),
                r[8*i + 4]);

            // r[8*i+5]  = (s->v[3*i+1] >> 7) & 7;
            r[8*i + 5] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 1], 7), FT::constant(7)),
                r[8*i + 5]);

            // r[8*i+5] ^= (s->v[3*i+2] << 1) & 7;
            r[8*i + 5] = FU::XOR(
                r[8*i + 5],
                FT::xword(
                    FT::AND(FT::SHL(m_v[3*i + 2], 1), FT::constant(7)),
                    r[8*i + 5]));

            // r[8*i+6]  = (s->v[3*i+2] >> 2) & 7;
            r[8*i + 6] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 2], 2), FT::constant(7)),
                r[8*i + 6]);

            // r[8*i+7]  = (s->v[3*i+2] >> 5) & 7;
            r[8*i + 7] = FT::xword(
                FT::AND(FT::SHR(m_v[3*i + 2], 5), FT::constant(7)),
                r[8*i + 7]);
        }

        // r[8*i+0]  =  s->v[3*i+0]       & 7;
        r[8*i + 0] = FT::xword(
            FT::AND(m_v[3*i + 0], FT::constant(7)),
            r[8*i + 0]);

        // r[8*i+1]  = (s->v[3*i+0] >> 3) & 7;
        r[8*i + 1] = FT::xword(
            FT::AND(FT::SHR(m_v[3*i + 0], 3), FT::constant(7)),
            r[8*i + 1]);

        // r[8*i+2]  = (s->v[3*i+0] >> 6) & 7;
        r[8*i + 2] = FT::xword(
            FT::AND(FT::SHR(m_v[3*i + 0], 6), FT::constant(7)),
            r[8*i + 2]);

        // r[8*i+2] ^= (s->v[3*i+1] << 2) & 7;
        r[8*i + 2] = FU::XOR(
            r[8*i + 2],
            FT::xword(
                FT::AND(FT::SHL(m_v[3*i + 1], 2), FT::constant(7)),
                r[8*i + 2]));

        // r[8*i+3]  = (s->v[3*i+1] >> 1) & 7;
        r[8*i + 3] = FT::xword(
            FT::AND(FT::SHR(m_v[3*i + 1], 1), FT::constant(7)),
            r[8*i + 3]);

        // r[8*i+4]  = (s->v[3*i+1] >> 4) & 7;
        r[8*i + 4] = FT::xword(
            FT::AND(FT::SHR(m_v[3*i + 1], 4), FT::constant(7)),
            r[8*i + 4]);

        // Making it signed

        // carry = 0;
        U carry = FU::constant(0);

        for (i = 0; i < 84; ++i) {
            // r[i] += carry;
            r[i] = FU::ADDMOD(r[i], carry);

            // r[i+1] += r[i] >> 3;
            r[i + 1] = FU::ADDMOD(r[i + 1], FU::SHR(r[i], 3));

            // r[i] &= 7;
            r[i] = FU::AND(r[i], FU::constant(7));

            // carry = r[i] >> 2;
            carry = FU::SHR(r[i], 2);

            // r[i] -= carry<<3;
            r[i] = FU::ADDMOD(r[i], FU::negate(FU::SHL(carry, 3)));
        }

        // r[84] += carry;
        r[84] = FU::ADDMOD(r[84], carry);
    }
    
    void window5(std::array<U, 51>& r) {
        std::size_t i;

        for (i = 0; i < 6; ++i) {
            // r[8*i+0]  =  s->v[5*i+0]       & 31;
            r[8*i + 0] = FT::xword(
                FT::AND(m_v[5*i + 0], FT::constant(31)),
                r[8*i + 0]);

            // r[8*i+1]  = (s->v[5*i+0] >> 5) & 31;
            r[8*i + 1] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 0], 5), FT::constant(31)),
                r[8*i + 1]);

            // r[8*i+1] ^= (s->v[5*i+1] << 3) & 31;
            r[8*i + 1] = FU::XOR(
                r[8*i + 1],
                FT::xword(
                    FT::AND(FT::SHL(m_v[5*i + 1], 3), FT::constant(31)),
                    r[8*i + 1]));

            // r[8*i+2]  = (s->v[5*i+1] >> 2) & 31;
            r[8*i + 2] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 1], 2), FT::constant(31)),
                r[8*i + 2]);

            // r[8*i+3]  = (s->v[5*i+1] >> 7) & 31;
            r[8*i + 3] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 1], 7), FT::constant(31)),
                r[8*i + 3]);

            // r[8*i+3] ^= (s->v[5*i+2] << 1) & 31;
            r[8*i + 3] = FU::XOR(
                r[8*i + 3],
                FT::xword(
                    FT::AND(FT::SHL(m_v[5*i + 2], 1), FT::constant(31)),
                    r[8*i + 3]));

            // r[8*i+4]  = (s->v[5*i+2] >> 4) & 31;
            r[8*i + 4] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 2], 4), FT::constant(31)),
                r[8*i + 4]);

            // r[8*i+4] ^= (s->v[5*i+3] << 4) & 31;
            r[8*i + 4] = FU::XOR(
                r[8*i + 4],
                FT::xword(
                    FT::AND(FT::SHL(m_v[5*i + 3], 4), FT::constant(31)),
                    r[8*i + 4]));

            // r[8*i+5]  = (s->v[5*i+3] >> 1) & 31;
            r[8*i + 5] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 3], 1), FT::constant(31)),
                r[8*i + 5]);

            // r[8*i+6]  = (s->v[5*i+3] >> 6) & 31;
            r[8*i + 6] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 6], 1), FT::constant(31)),
                r[8*i + 6]);

            // r[8*i+6] ^= (s->v[5*i+4] << 2) & 31;
            r[8*i + 6] = FU::XOR(
                r[8*i + 6],
                FT::xword(
                    FT::AND(FT::SHL(m_v[5*i + 4], 2), FT::constant(31)),
                    r[8*i + 6]));

            // r[8*i+7]  = (s->v[5*i+4] >> 3) & 31;
            r[8*i + 7] = FT::xword(
                FT::AND(FT::SHR(m_v[5*i + 4], 3), FT::constant(31)),
                r[8*i + 7]);
        }

        // r[8*i+0]  =  s->v[5*i+0]       & 31;
        r[8*i + 0] = FT::xword(
            FT::AND(m_v[5*i + 0], FT::constant(31)),
            r[8*i + 0]);

        // r[8*i+1]  = (s->v[5*i+0] >> 5) & 31;
        r[8*i + 1] = FT::xword(
            FT::AND(FT::SHR(m_v[5*i + 0], 5), FT::constant(31)),
            r[8*i + 1]);

        // r[8*i+1] ^= (s->v[5*i+1] << 3) & 31;
        r[8*i + 1] = FU::XOR(
            r[8*i + 1],
            FT::xword(
                FT::AND(FT::SHL(m_v[5*i + 1], 3), FT::constant(31)),
                r[8*i + 1]));

        // r[8*i+2]  = (s->v[5*i+1] >> 2) & 31;
        r[8*i + 2] = FT::xword(
            FT::AND(FT::SHR(m_v[5*i + 1], 2), FT::constant(31)),
            r[8*i + 2]);

        // Making it signed

        // carry = 0;
        U carry = FU::constant(0);

        for (i = 0; i < 50; ++i) {
            // r[i] += carry;
            r[i] = FU::ADDMOD(r[i], carry);

            // r[i+1] += r[i] >> 5;
            r[i + 1] = FU::ADDMOD(r[i + 1], FU::SHR(r[i], 5));

            // r[i] &= 31;
            r[i] = FU::AND(r[i], FU::constant(31));

            // carry = r[i] >> 4;
            carry = FU::SHR(r[i], 4);

            // r[i] -= carry<<5;
            r[i] = FU::ADDMOD(r[i], FU::negate(FU::SHL(carry, 5)));
        }

        // r[50] += carry;
        r[50] = FU::ADDMOD(r[50], carry);
    }

    void interleave2(std::array<U, 127>& r, const sc25519& s2) {
        for (std::size_t i = 0; i < 31; ++i) {
            // r[4*i]   = ( s1->v[i]       & 3) ^ (( s2->v[i]       & 3) << 2);
            r[4*i] = FU::XOR(
                FT::xword(FT::AND(m_v[i], FT::constant(3)),
                          r[4*i]),
                FT::xword(FT::SHL(FT::AND(s2.m_v[i], FT::constant(3)), 2),
                          r[4*i]));

            // r[4*i+1] = ((s1->v[i] >> 2) & 3) ^ (((s2->v[i] >> 2) & 3) << 2);
            r[4*i + 1] = FU::XOR(
                FT::xword(FT::AND(FT::SHR(m_v[i], 2), FT::constant(3)),
                          r[4*i + 1]),
                FT::xword(FT::SHL(FT::AND(FT::SHR(s2.m_v[i], 2), FT::constant(3)), 2),
                          r[4*i + 1]));

            // r[4*i+2] = ((s1->v[i] >> 4) & 3) ^ (((s2->v[i] >> 4) & 3) << 2);
            r[4*i + 2] = FU::XOR(
                FT::xword(FT::AND(FT::SHR(m_v[i], 4), FT::constant(3)),
                          r[4*i + 2]),
                FT::xword(FT::SHL(FT::AND(FT::SHR(s2.m_v[i], 4), FT::constant(3)), 2),
                          r[4*i + 2]));

            // r[4*i+3] = ((s1->v[i] >> 6) & 3) ^ (((s2->v[i] >> 6) & 3) << 2);
            r[4*i + 3] = FU::XOR(
                FT::xword(FT::AND(FT::SHR(m_v[i], 6), FT::constant(3)),
                          r[4*i + 3]),
                FT::xword(FT::SHL(FT::AND(FT::SHR(s2.m_v[i], 6), FT::constant(3)), 2),
                          r[4*i + 3]));
        }

        // r[124] = ( s1->v[31]       & 3) ^ (( s2->v[31]       & 3) << 2);
        r[124] = FU::XOR(
            FT::xword(FT::AND(m_v[31], FT::constant(3)),
                      r[124]),
            FT::xword(FT::SHL(FT::AND(s2.m_v[31], FT::constant(3)), 2),
                      r[124]));

        // r[125] = ((s1->v[31] >> 2) & 3) ^ (((s2->v[31] >> 2) & 3) << 2);
        r[125] = FU::XOR(
            FT::xword(FT::AND(FT::SHR(m_v[31], 2), FT::constant(3)),
                      r[125]),
            FT::xword(FT::SHL(FT::AND(FT::SHR(s2.m_v[31], 2), FT::constant(3)), 2),
                      r[125]));

        // r[126] = ((s1->v[31] >> 4) & 3) ^ (((s2->v[31] >> 4) & 3) << 2);
        r[126] = FU::XOR(
            FT::xword(FT::AND(FT::SHR(m_v[31], 4), FT::constant(3)),
                      r[126]),
            FT::xword(FT::SHL(FT::AND(FT::SHR(s2.m_v[31], 4), FT::constant(3)), 2),
                      r[126]));
    }

private:
    static T lt(const T& a, const T& b) { // 16-bit inputs
        // 0: no; 1: yes
        return FT::xword(
            // most significant bit of (a - b)
            FT::testbit(
                FT::ADDMOD(a, FT::negate(b)), 31));
    }

    void reduce_add_sub() {
        const std::array<std::uint32_t, 32> m = {
            0xED, 0xD3, 0xF5,
            0x5C, 0x1A, 0x63,
            0x12, 0x58, 0xD6,
            0x9C, 0xF7, 0xA2,
            0xDE, 0xF9, 0xDE,
            0x14, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x10 };

        T pb = FT::constant(0), b, mask;
        std::array<T, 32> t;

        for (std::size_t i = 0; i < 32; ++i) {
            // pb += m[i];
            pb = FT::ADDMOD(pb, FT::constant(m[i]));

            // b = lt(r->v[i],pb);
            b = lt(m_v[i], pb);

            // t[i] = r->v[i]-pb+(b<<8);
            t[i] = FT::ADDMOD(m_v[i],
                              FT::ADDMOD(FT::negate(pb),
                                         FT::SHL(b, 8)));

            // pb = b;
            pb = b;
        }

        // mask = b - 1;
        mask = FT::ADDMOD(b, FT::constant(-1));

        for (std::size_t i = 0; i < 32; ++i) {
            // r->v[i] ^= mask & (r->v[i] ^ t[i]);
            m_v[i] = FT::XOR(m_v[i],
                             FT::AND(mask,
                                     FT::XOR(m_v[i], t[i])));
        }
    }

    // Reduce coefficients of x before calling barrett_reduce
    void barrett_reduce(const std::array<T, 64>& x) {
        const std::array<std::uint32_t, 32> m = {
            0xED, 0xD3, 0xF5,
            0x5C, 0x1A, 0x63,
            0x12, 0x58, 0xD6,
            0x9C, 0xF7, 0xA2,
            0xDE, 0xF9, 0xDE,
            0x14, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x10 };

        const std::array<std::uint32_t, 33> mu = {
            0x1B, 0x13, 0x2C,
            0x0A, 0xA3, 0xE5,
            0x9C, 0xED, 0xA7,
            0x29, 0x63, 0x08,
            0x5D, 0x21, 0x06,
            0x21, 0xEB, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x0F };

        // See HAC, Alg. 14.42
        std::array<T, 66> q2 = FT::zero(q2);
        std::array<T, 33> r1, r2 = FT::zero(r2);
        T carry, pb = FT::constant(0), b;

        // for(i=0;i<33;i++)
        //   for(j=0;j<33;j++)
        //     if(i+j >= 31) q2[i+j] += mu[i]*x[j+31];
        for (std::size_t i = 0; i < 33; ++i) {
            for (std::size_t j = 0; j < 33; ++j) {
                if (i + j >= 31)
                    q2[i + j] = FT::ADDMOD(
                        q2[i + j],
                        FT::MULMOD(FT::constant(mu[i]), x[j + 31]));
            }
        }

        // carry = q2[31] >> 8;
        carry = FT::SHR(q2[31], 8);

        // q2[32] += carry;
        q2[32] = FT::ADDMOD(q2[32], carry);

        // carry = q2[32] >> 8;
        carry = FT::SHR(q2[32], 8);

        // q2[33] += carry;
        q2[33] = FT::ADDMOD(q2[33], carry);

        // for(i=0;i<33;i++)r1[i] = x[i];
        for (std::size_t i = 0; i < 33; ++i) r1[i] = x[i];

        for (std::size_t i = 0; i < 32; ++i) {
            for (std::size_t j = 0; j < 33; ++j) {
                // if(i+j < 33) r2[i+j] += m[i]*q3[j];
                if (i + j < 33)
                    r2[i + j] = FT::ADDMOD(
                        r2[i + j],
                        FT::MULMOD(FT::constant(m[i]), q2[j + 33]));
                // crypto_uint32 *q3 = q2 + 33;
            }
        }

        for (std::size_t i = 0; i < 32; ++i) {
            // carry = r2[i] >> 8;
            carry = FT::SHR(r2[i], 8);

            // r2[i+1] += carry;
            r2[i + 1] = FT::ADDMOD(r2[i + 1], carry);

            // r2[i] &= 0xff;
            r2[i] = FT::AND(r2[i], FT::constant(0xff));
        }

        for (std::size_t i = 0; i < 32; ++i) {
            // pb += r2[i];
            pb = FT::ADDMOD(pb, r2[i]);

            // b = lt(r1[i],pb);
            b = lt(r1[i], pb);

            // r->v[i] = r1[i]-pb+(b<<8);
            m_v[i] = FT::ADDMOD(r1[i],
                                FT::ADDMOD(FT::negate(pb),
                                           FT::SHL(b, 8)));

            // pb = b;
            pb = b;
        }

        // XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
        // If so: Handle  it here!

        // reduce_add_sub(r);
        // reduce_add_sub(r);
        reduce_add_sub();
        reduce_add_sub();
    }

    std::array<T, 32> m_v;
};

} // namespace cryptl

#endif
