#ifndef _CRYPTL_ED25519_FE_HPP_
#define _CRYPTL_ED25519_FE_HPP_

#include <array>
#include <cstdint>

namespace cryptl {

// direct translation of: supercop-20141124/crypto_sign/ed25519/ref/fe25519.c

////////////////////////////////////////////////////////////////////////////////
// fe25519
//

// T is 32-bit, U is 8-bit, B is bool, F is Bitwise, NS is namespace
template <typename T, typename U, typename B, typename F, typename NS>
class fe25519
{
public:
    fe25519() = default;

    // specifically needed for ge25519 constants and lookup tables
    fe25519(const std::array<std::uint8_t, 32>& a) {
        for (std::size_t i = 0; i < 32; ++i)
            m_v[i] = F::constant(a[i]);
    }

    const T& operator[] (const std::size_t i) const {
        return m_v[i];
    }

    T& operator[] (const std::size_t i) {
        return m_v[i];
    }

    // reduction modulo 2^255-19
    void freeze() {
        // crypto_uint32 m = equal(r->v[31],127);
        T m = equal(m_v[31], 127);

        for (std::size_t i = 30; i > 0; --i) {
            // m &= equal(r->v[i],255);
            m = F::AND(m, equal(m_v[i], 255));
        }

        // m &= ge(r->v[0],237);
        m = F::AND(m, ge(m_v[0], 237));

        // m = -m;
        m = F::negate(m);

        // r->v[31] -= m&127;
        m_v[31] = F::ADDMOD(m_v[31], F::negate(F::AND(m, F::constant(127))));

        for (std::size_t i = 30; i > 0; --i) {
            // r->v[i] -= m&255;
            m_v[i] = F::ADDMOD(m_v[i], F::negate(F::AND(m, F::constant(255))));
        }

        // r->v[0] -= m&237;
        m_v[0] = F::ADDMOD(m_v[0], F::negate(F::AND(m, F::constant(237))));
    }

    // initialize from byte array
    void unpack(const std::array<U, 32>& x) {
        for (std::size_t i = 0; i < 32; ++i) {
            // r->v[i] = x[i];
            m_v[i] = F::xword(x[i], m_v[i]);
        }

        // r->v[31] &= 127;
        m_v[31] = F::AND(m_v[31], F::constant(127));
    }

    // Assumes input x being reduced below 2^255
    // (note: input x is *this)
    void pack(std::array<U, 32>& r) {
        // fe25519 y = *x;
        auto y(*this);

        // fe25519_freeze(&y);
        y.freeze();

        for (std::size_t i = 0; i < 32; ++i) {
            // r[i] = y.v[i];
            r[i] = F::xword(y.m_v[i], r[i]);
        }
    }

    B iszero() {
        // fe25519 t = *x;
        auto t(*this);

        // fe25519_freeze(&t);
        t.freeze();

        // same as supercop in circuit form except not equal test
        return F::logicalNOT(
            NS::notequal(t.m_v, F::zero(t.m_v))); // inequality test is imperative
    }

    B iseq_vartime(const fe25519& y) {
        // fe25519 t1 = *x;
        auto t1(*this);

        // fe25519 t2 = *y;
        auto t2(y);

        // fe25519_freeze(&t1);
        t1.freeze();

        // fe25519_freeze(&t2);
        t2.freeze();

        // same as supercop in circuit form
        return F::logicalNOT(
            NS::notequal(t1.m_v, t2.m_v)); // inequality test is imperative
    }

    void cmov(const fe25519& x, const B& b) {
        // crypto_uint32 mask = b;
        T mask = F::xword(b);

        // mask = -mask;
        mask = F::negate(mask);

        for (std::size_t i = 0; i < 32; ++i) {
            // r->v[i] ^= mask & (x->v[i] ^ r->v[i]);
            m_v[i] = F::XOR(m_v[i],
                            F::AND(mask,
                                   F::XOR(x.m_v[i], m_v[i])));
        }
    }

    B getparity() {
        // fe25519 t = *x;
        auto t(*this);

        // fe25519_freeze(&t);
        t.freeze();

        // return t.v[0] & 1;
        return F::testbit(t.m_v[0], 0);
    }

    void setone() {
        // r->v[0] = 1;
        m_v[0] = F::constant(1);

        for (std::size_t i = 1; i < 32; ++i) {
            // r->v[i]=0;
            m_v[i] = F::constant(0);
        }
    }

    void setzero() {
        // for(i=0;i<32;i++) r->v[i]=0;
        m_v = F::zero(m_v);
    }

    void neg(const fe25519& x) {
        // fe25519 t;
        // for(i=0;i<32;i++) t.v[i]=x->v[i];
        auto t(x);

        // fe25519_setzero(r);
        setzero();

        // fe25519_sub(r, r, &t);
        sub(*this, t);
    }

    void add(const fe25519& x, const fe25519& y) {
        for (std::size_t i = 0; i < 32; ++i) {
            // r->v[i] = x->v[i] + y->v[i];
            m_v[i] = F::ADDMOD(x.m_v[i], y.m_v[i]);
        }

        // reduce_add_sub(r);
        reduce_add_sub();
    }

    void sub(const fe25519& x, const fe25519& y) {
        // crypto_uint32 t[32];
        std::array<T, 32> t;

        // t[0] = x->v[0] + 0x1da;
        t[0] = F::ADDMOD(x.m_v[0], F::constant(0x1da));

        // t[31]= x->v[31] + 0xfe;
        t[31] = F::ADDMOD(x.m_v[31], F::constant(0xfe));

        for (std::size_t i = 1; i < 31; ++i) {
            // t[i] = x->v[i] + 0x1fe;
            t[i] = F::ADDMOD(x.m_v[i], F::constant(0x1fe));
        }

        for (std::size_t i = 0; i < 32; ++i) {
            // r->v[i] = t[i] - y->v[i];
            m_v[i] = F::ADDMOD(t[i], F::negate(y.m_v[i]));
        }

        // reduce_add_sub(r);
        reduce_add_sub();
    }

    void mul(const fe25519& x, const fe25519& y) {
        // crypto_uint32 t[63];
        // for(i=0;i<63;i++)t[i] = 0;
        std::array<T, 63> t = F::zero(t);

        for (std::size_t i = 0; i < 32; ++i) {
            for (std::size_t j = 0; j < 32; ++j) {
                // t[i+j] += x->v[i] * y->v[j];
                t[i + j] = F::ADDMOD(t[i + j],
                                     F::MULMOD(x.m_v[i],
                                               y.m_v[j]));
            }
        }

        for (std::size_t i = 32; i < 63; ++i) {
            // r->v[i-32] = t[i-32] + times38(t[i]);
            m_v[i - 32] = F::ADDMOD(t[i - 32], times38(t[i]));
        }

        // r->v[31] = t[31]; /* result now in r[0]...r[31] */
        m_v[31] = t[31];

        // reduce_mul(r);
        reduce_mul();
    }

    void square(const fe25519& x) {
        // fe25519_mul(r, x, x)
        mul(x, x);
    }

    void invert(const fe25519& x) {
        fe25519
            z2, z9, z11,
            z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0,
            t0, t1;

	// /* 2 */ fe25519_square(&z2,x);
        z2.square(x);

	// /* 4 */ fe25519_square(&t1,&z2);
        t1.square(z2);

	// /* 8 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 9 */ fe25519_mul(&z9,&t0,x);
        z9.mul(t0, x);

        // /* 11 */ fe25519_mul(&z11,&z9,&z2);
        z11.mul(z9, z2);

        // /* 22 */ fe25519_square(&t0,&z11);
        t0.square(z11);

        // /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,&t0,&z9);
        z2_5_0.mul(t0, z9);

        // /* 2^6 - 2^1 */ fe25519_square(&t0,&z2_5_0);
        t0.square(z2_5_0);

        // /* 2^7 - 2^2 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^8 - 2^3 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 2^9 - 2^4 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^10 - 2^5 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,&t0,&z2_5_0);
        z2_10_0.mul(t0, z2_5_0);

	// /* 2^11 - 2^1 */ fe25519_square(&t0,&z2_10_0);
        t0.square(z2_10_0);

        // /* 2^12 - 2^2 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
        for (std::size_t i = 2; i < 10; i += 2) {
            t0.square(t1);
            t1.square(t0);
        }

        // /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,&t1,&z2_10_0);
        z2_20_0.mul(t1, z2_10_0);

	// /* 2^21 - 2^1 */ fe25519_square(&t0,&z2_20_0);
        t0.square(z2_20_0);

        // /* 2^22 - 2^2 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
        for (std::size_t i = 2; i < 20; i += 2) {
            t0.square(t1);
            t1.square(t0);
        }

        // /* 2^40 - 2^0 */ fe25519_mul(&t0,&t1,&z2_20_0);
        t0.mul(t1, z2_20_0);

	// /* 2^41 - 2^1 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^42 - 2^2 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t1,&t0); fe25519_square(&t0,&t1); }
        for (std::size_t i = 2; i < 10; i += 2) {
            t1.square(t0);
            t0.square(t1);
        }

        // /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,&t0,&z2_10_0);
        z2_50_0.mul(t0, z2_10_0);

	// /* 2^51 - 2^1 */ fe25519_square(&t0,&z2_50_0);
        t0.square(z2_50_0);

        // /* 2^52 - 2^2 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
        for (std::size_t i = 2; i < 50; i += 2) {
            t0.square(t1);
            t1.square(t0);
        }

        // /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,&t1,&z2_50_0);
        z2_100_0.mul(t1, z2_50_0);

	// /* 2^101 - 2^1 */ fe25519_square(&t1,&z2_100_0);
        t1.square(z2_100_0);

        // /* 2^102 - 2^2 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { fe25519_square(&t1,&t0); fe25519_square(&t0,&t1); }
        for (std::size_t i = 2; i < 100; i += 2) {
            t1.square(t0);
            t0.square(t1);
        }

        // /* 2^200 - 2^0 */ fe25519_mul(&t1,&t0,&z2_100_0);
        t1.mul(t0, z2_100_0);

	// /* 2^201 - 2^1 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 2^202 - 2^2 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
        for (std::size_t i = 2; i < 50; i += 2) {
            t0.square(t1);
            t1.square(t0);
        }

        // /* 2^250 - 2^0 */ fe25519_mul(&t0,&t1,&z2_50_0);
        t0.mul(t1, z2_50_0);

	// /* 2^251 - 2^1 */ fe25519_square(&t1,&t0);
        t1.square(t0);

        // /* 2^252 - 2^2 */ fe25519_square(&t0,&t1);
        t0.square(t1);

        // /* 2^253 - 2^3 */ fe25519_square(&t1,&t0);
        t1.square(t0);

	// /* 2^254 - 2^4 */ fe25519_square(&t0,&t1);
        t0.square(t1);

	// /* 2^255 - 2^5 */ fe25519_square(&t1,&t0);
        t1.square(t0);

	// /* 2^255 - 21 */ fe25519_mul(r,&t1,&z11);
        mul(t1, z11);
    }

    void pow2523(const fe25519& x) {
        fe25519
            z2, z9, z11,
            z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0,
            t;
		
	// /* 2 */ fe25519_square(&z2,x);
        z2.square(x);

        // /* 4 */ fe25519_square(&t,&z2);
        t.square(z2);

        // /* 8 */ fe25519_square(&t,&t);
        t.square(t);

        // /* 9 */ fe25519_mul(&z9,&t,x);
        z9.mul(t, x);

        // /* 11 */ fe25519_mul(&z11,&z9,&z2);
        z11.mul(z9, z2);

        // /* 22 */ fe25519_square(&t,&z11);
        t.square(z11);

        // /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,&t,&z9);
        z2_5_0.mul(t, z9);

	// /* 2^6 - 2^1 */ fe25519_square(&t,&z2_5_0);
        t.square(z2_5_0);

        // /* 2^10 - 2^5 */ for (i = 1;i < 5;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 5; ++i) {
            t.square(t);
        }

        // /* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,&t,&z2_5_0);
        z2_10_0.mul(t, z2_5_0);

	// /* 2^11 - 2^1 */ fe25519_square(&t,&z2_10_0);
        t.square(z2_10_0);

        // /* 2^20 - 2^10 */ for (i = 1;i < 10;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 10; ++i) {
            t.square(t);
        }

        // /* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,&t,&z2_10_0);
        z2_20_0.mul(t, z2_10_0);

	// /* 2^21 - 2^1 */ fe25519_square(&t,&z2_20_0);
        t.square(z2_20_0);

        // /* 2^40 - 2^20 */ for (i = 1;i < 20;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 20; ++i) {
            t.square(t);
        }

        // /* 2^40 - 2^0 */ fe25519_mul(&t,&t,&z2_20_0);
        t.mul(t, z2_20_0);

	// /* 2^41 - 2^1 */ fe25519_square(&t,&t);
        t.square(t);

        // /* 2^50 - 2^10 */ for (i = 1;i < 10;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 10; ++i) {
            t.square(t);
        }

        // /* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,&t,&z2_10_0);
        z2_50_0.mul(t, z2_10_0);

	// /* 2^51 - 2^1 */ fe25519_square(&t,&z2_50_0);
        t.square(z2_50_0);

        // /* 2^100 - 2^50 */ for (i = 1;i < 50;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 50; ++i) {
            t.square(t);
        }

        // /* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,&t,&z2_50_0);
        z2_100_0.mul(t, z2_50_0);

	// /* 2^101 - 2^1 */ fe25519_square(&t,&z2_100_0);
        t.square(z2_100_0);

        // /* 2^200 - 2^100 */ for (i = 1;i < 100;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 100; ++i) {
            t.square(t);
        }

        // /* 2^200 - 2^0 */ fe25519_mul(&t,&t,&z2_100_0);
        t.mul(t, z2_100_0);

	// /* 2^201 - 2^1 */ fe25519_square(&t,&t);
        t.square(t);

        // /* 2^250 - 2^50 */ for (i = 1;i < 50;i++) { fe25519_square(&t,&t); }
        for (std::size_t i = 1; i < 50; ++i) {
            t.square(t);
        }

        // /* 2^250 - 2^0 */ fe25519_mul(&t,&t,&z2_50_0);
        t.mul(t, z2_50_0);

	// /* 2^251 - 2^1 */ fe25519_square(&t,&t);
        t.square(t);

        // /* 2^252 - 2^2 */ fe25519_square(&t,&t);
        t.square(t);

	// /* 2^252 - 3 */ fe25519_mul(r,&t,x);
        mul(t, x);
    }

private:
    static T equal(const T& a, const std::uint32_t b) { // 16-bit inputs
        // 1: yes; 0: no
        return F::xword(
            F::logicalNOT(
                a != F::constant(b))); // inequality test is imperative
    }

    static T ge(const T& a, const std::uint32_t b) { // 16-bit inputs
        // 1: yes; 0: no
        return F::xword(
            // complement most significant bit of (a - b)
            F::logicalNOT(
                F::testbit(
                    F::ADDMOD(a, F::constant(-b)), 31)));
    }

    static T times19(const T& a) {
        // return (a << 4) + (a << 1) + a;
        return F::ADDMOD(
            F::_ADDMOD(F::_SHL(a, 4), F::_SHL(a, 1)),
            a);
    }

    static T times38(const T& a) {
        // return (a << 5) + (a << 2) + (a << 1);
        return F::ADDMOD(
            F::_ADDMOD(F::_SHL(a, 5), F::_SHL(a, 2)),
            F::_SHL(a, 1));
    }

    void reduce_add_sub() {
        for (std::size_t rep = 0; rep < 4; ++rep) {
            // t = r->v[31] >> 7;
            T t = F::SHR(m_v[31], 7);

            // r->v[31] &= 127;
            m_v[31] = F::AND(m_v[31], F::constant(127));

            // t = times19(t);
            t = times19(t);

            // r->v[0] += t;
            m_v[0] = F::ADDMOD(m_v[0], t);

            for (std::size_t i = 0; i < 31; ++i) {
                // t = r->v[i] >> 8;
                t = F::SHR(m_v[i], 8);

                // r->v[i+1] += t;
                m_v[i+1] = F::ADDMOD(m_v[i+1], t);

                // r->v[i] &= 255;
                m_v[i] = F::AND(m_v[i], F::constant(255));
            }
        }
    }

    void reduce_mul() {
        for (std::size_t rep = 0; rep < 2; ++rep) {
            // t = r->v[31] >> 7;
            T t = F::SHR(m_v[31], 7);

            // r->v[31] &= 127;
            m_v[31] = F::AND(m_v[31], F::constant(127));

            // t = times19(t);
            t = times19(t);

            // r->v[0] += t;
            m_v[0] = F::ADDMOD(m_v[0], t);

            for(std::size_t i = 0; i < 31; ++i) {
                // t = r->v[i] >> 8;
                t = F::SHR(m_v[i], 8);

                // r->v[i+1] += t;
                m_v[i+1] = F::ADDMOD(m_v[i+1], t);

                // r->v[i] &= 255;
                m_v[i] = F::AND(m_v[i], F::constant(255));
            }
        }
    }

    std::array<T, 32> m_v;
};

} // namespace cryptl

#endif
