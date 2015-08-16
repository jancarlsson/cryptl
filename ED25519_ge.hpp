#ifndef _CRYPTL_ED25519_GE_HPP_
#define _CRYPTL_ED25519_GE_HPP_

#include <array>
#include <cstdint>

#include <cryptl/ED25519_fe.hpp>
#include <cryptl/ED25519_sc.hpp>

namespace cryptl {

// direct translation of: supercop-20141124/crypto_sign/ed25519/ref/ge25519.c

////////////////////////////////////////////////////////////////////////////////
// ge25519_aff
//

// T is 32-bit, U is 8-bit, B is bool
// FT is Bitwise for 32-bit
// FU is Bitwise for 8-bit
// NS is namespace
template <typename T, typename U, typename B, typename FT, typename FU, typename NS>
class ge25519_aff
{
    typedef std::uint8_t U8;

public:
    ge25519_aff() = default;

    ge25519_aff(const fe25519<T, U, B, FT, NS>& x,
                const fe25519<T, U, B, FT, NS>& y)
        : m_x(x),
          m_y(y)
    {}

    ge25519_aff(const U8 x00, const U8 x01, const U8 x02, const U8 x03,
                const U8 x04, const U8 x05, const U8 x06, const U8 x07,
                const U8 x08, const U8 x09, const U8 x10, const U8 x11,
                const U8 x12, const U8 x13, const U8 x14, const U8 x15,
                const U8 x16, const U8 x17, const U8 x18, const U8 x19,
                const U8 x20, const U8 x21, const U8 x22, const U8 x23,
                const U8 x24, const U8 x25, const U8 x26, const U8 x27,
                const U8 x28, const U8 x29, const U8 x30, const U8 x31,
                const U8 y00, const U8 y01, const U8 y02, const U8 y03,
                const U8 y04, const U8 y05, const U8 y06, const U8 y07,
                const U8 y08, const U8 y09, const U8 y10, const U8 y11,
                const U8 y12, const U8 y13, const U8 y14, const U8 y15,
                const U8 y16, const U8 y17, const U8 y18, const U8 y19,
                const U8 y20, const U8 y21, const U8 y22, const U8 y23,
                const U8 y24, const U8 y25, const U8 y26, const U8 y27,
                const U8 y28, const U8 y29, const U8 y30, const U8 y31)
        : m_x({x00, x01, x02, x03, x04, x05, x06, x07,
               x08, x09, x10, x11, x12, x13, x14, x15,
               x16, x17, x18, x19, x20, x21, x22, x23,
               x24, x25, x26, x27, x28, x29, x30, x31}),
          m_y({y00, y01, y02, y03, y04, y05, y06, y07,
               y08, y09, y10, y11, y12, y13, y14, y15,
               y16, y17, y18, y19, y20, y21, y22, y23,
               y24, y25, y26, y27, y28, y29, y30, y31})
    {}

    void choose_t(const std::size_t pos, const U& b) {
        // *t = ge25519_base_multiples_affine[5*pos+0];
        *this = base_multiples_affine(5*pos + 0);

        // cmov_aff(t, &ge25519_base_multiples_affine[5*pos+1],equal(b,1) | equal(b,-1));
        cmov_aff(base_multiples_affine(5*pos + 1), equal(b, 1) || equal(b, -1));

        // cmov_aff(t, &ge25519_base_multiples_affine[5*pos+2],equal(b,2) | equal(b,-2));
        cmov_aff(base_multiples_affine(5*pos + 2), equal(b, 2) || equal(b, -2));

        // cmov_aff(t, &ge25519_base_multiples_affine[5*pos+3],equal(b,3) | equal(b,-3));
        cmov_aff(base_multiples_affine(5*pos + 3), equal(b, 3) || equal(b, -3));

        // cmov_aff(t, &ge25519_base_multiples_affine[5*pos+4],equal(b,-4));
        cmov_aff(base_multiples_affine(5*pos + 4), equal(b, -4));

        fe25519<T, U, B, FT, NS> v;

        // fe25519_neg(&v, &t->x);
        v.neg(m_x);

        // fe25519_cmov(&t->x, &v, negative(b));
        m_x.cmov(v, FU::testbit(b, 7));
    }

    const fe25519<T, U, B, FT, NS>& x() const {
        return m_x;
    }

    const fe25519<T, U, B, FT, NS>& y() const {
        return m_y;
    }

private:
    static B equal(const U& b, const std::uint8_t c) {
        // 1: yes; 0: no
        return FU::logicalNOT(
            b != FU::constant(c));
    }

    // Multiples of the base point in affine representation
    static const ge25519_aff& base_multiples_affine(const std::size_t i) {
        typedef ge25519_aff A;
        const std::size_t N = 425 / 5;

        if (i < N) {
            static const std::array<A, 425/5> a1{
#include <cryptl/ED25519_gebase1.hpp>
            };
            return a1[i];

        } else if (i < 2 * N) {
            static const std::array<A, 425/5> a2{
#include <cryptl/ED25519_gebase2.hpp>
            };
            return a2[i - N];

        } else if (i < 3 * N) {
            static const std::array<A, 425/5> a3{
#include <cryptl/ED25519_gebase3.hpp>
            };
            return a3[i - 2 * N];

        } else if (i < 4 * N) {
            static const std::array<A, 425/5> a4{
#include <cryptl/ED25519_gebase4.hpp>
            };
            return a4[i - 3 * N];

        } else {
            static const std::array<A, 425/5> a5{
#include <cryptl/ED25519_gebase5.hpp>
            };
            return a5[i - 4 * N];
        }
    }

    // cmov_aff()
    // Constant-time version of: if(b) r = p
    void cmov_aff(const ge25519_aff& p, const B& b) {
        // fe25519_cmov(&r->x, &p->x, b);
        m_x.cmov(p.x(), b);

        // fe25519_cmov(&r->y, &p->y, b);
        m_y.cmov(p.y(), b);
    }

    fe25519<T, U, B, FT, NS> m_x, m_y;
};

////////////////////////////////////////////////////////////////////////////////
// ge25519
//

// T is 32-bit, U is 8-bit, B is bool
// FT is Bitwise for 32-bit
// FU is Bitwise for 8-bit
// NS is namespace
template <typename T, typename U, typename B, typename FT, typename FU, typename NS>
class ge25519
{
public:
    ge25519() = default;

    ge25519(const std::array<std::uint8_t, 32>& x,
            const std::array<std::uint8_t, 32>& y,
            const std::array<std::uint8_t, 32>& z,
            const std::array<std::uint8_t, 32>& t)
        : m_x(x),
          m_y(y),
          m_z(z),
          m_t(t)
    {}

    B unpackneg_vartime(const std::array<U, 32>& p) {
        // d
        static const fe25519<T, U, B, FT, NS> ge25519_ecd({
            0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75,
            0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00, 
            0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C,
            0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52 });

        // sqrt(-1)
        static const fe25519<T, U, B, FT, NS> ge25519_sqrtm1({
            0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4,
            0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43, 0x2F, 
            0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B,
            0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B });

        fe25519<T, U, B, FT, NS> t, chk, num, den, den2, den4, den6;

        // fe25519_setone(&r->z);
        m_z.setone();

        // fe25519_unpack(&r->y, p); 
        m_y.unpack(p);

        // fe25519_square(&num, &r->y); /* x = y^2 */
        num.square(m_y);

        // fe25519_mul(&den, &num, &ge25519_ecd); /* den = dy^2 */
        den.mul(num, ge25519_ecd);

        // fe25519_sub(&num, &num, &r->z); /* x = y^2-1 */
        num.sub(num, m_z);

        // fe25519_add(&den, &r->z, &den); /* den = dy^2+1 */
        den.add(m_z, den);

        // Computation of sqrt(num/den)
        // 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8)

        //fe25519_square(&den2, &den);
        den2.square(den);

        // fe25519_square(&den4, &den2);
        den4.square(den2);

        // fe25519_mul(&den6, &den4, &den2);
        den6.mul(den4, den2);

        // fe25519_mul(&t, &den6, &num);
        t.mul(den6, num);

        // fe25519_mul(&t, &t, &den);
        t.mul(t, den);

        // fe25519_pow2523(&t, &t);
        t.pow2523(t);

        // 2. computation of r->x = t * num * den^3

        // fe25519_mul(&t, &t, &num);
        t.mul(t, num);

        // fe25519_mul(&t, &t, &den);
        t.mul(t, den);

        // fe25519_mul(&t, &t, &den);
        t.mul(t, den);

        // fe25519_mul(&r->x, &t, &den);
        m_x.mul(t, den);

        // 3. Check whether sqrt computation gave correct result,
        // multiply by sqrt(-1) if not:

        // fe25519_square(&chk, &r->x);
        chk.square(m_x);

        // fe25519_mul(&chk, &chk, &den);
        chk.mul(chk, den);

        // if (!fe25519_iseq_vartime(&chk, &num))
        //   fe25519_mul(&r->x, &r->x, &ge25519_sqrtm1);
        const B b3 = chk.iseq_vartime(num);
        fe25519<T, U, B, FT, NS> x3;
        x3.mul(m_x, ge25519_sqrtm1);
        for (std::size_t i = 0; i < 32; ++i) {
            m_x[i] = FT::ternary(b3, m_x[i], x3[i]);
        }

        // 4. Now we have one of the two square roots, except if input was not a square

        // fe25519_square(&chk, &r->x);
        chk.square(m_x);

        // fe25519_mul(&chk, &chk, &den);
        chk.mul(chk, den);

        // if (!fe25519_iseq_vartime(&chk, &num))
        //   return -1;
        const B b4 = chk.iseq_vartime(num);

        // 5. Choose the desired square root according to parity:

        // unsigned char par;
        // par = p[31] >> 7;
        // if(fe25519_getparity(&r->x) != (1-par))
        //   fe25519_neg(&r->x, &r->x);
        const B b5 = m_x.getparity() == FU::testbit(p[31], 7);
        const B b45 = FT::AND(b4, b5);
        fe25519<T, U, B, FT, NS> x5 = m_x;
        x5.neg(x5);
        for (std::size_t i = 0; i < 32; ++i) {
            m_x[i] = FT::ternary(b45, x5[i], m_x[i]);
        }

        // fe25519_mul(&r->t, &r->x, &r->y);
        fe25519<T, U, B, FT, NS> t5;
        t5.mul(m_x, m_y);
        for (std::size_t i = 0; i < 32; ++i) {
            m_t[i] = FT::ternary(b4, t5[i], m_t[i]);
        }

        // return 0;
        return b4;
    }

    void pack(std::array<U, 32>& r) const {
        fe25519<T, U, B, FT, NS> tx, ty, zi;

        // fe25519_invert(&zi, &p->z);
        zi.invert(m_z);

        // fe25519_mul(&tx, &p->x, &zi);
        tx.mul(m_x, zi);

        // fe25519_mul(&ty, &p->y, &zi);
        ty.mul(m_y, zi);

        // fe25519_pack(r, &ty);
        ty.pack(r);

        // r[31] ^= fe25519_getparity(&tx) << 7;
        r[31] = FU::XOR(
            r[31],
            FU::ternary(tx.getparity(),
                        FU::constant(128),
                        FU::constant(0)));
    }

    B isneutral_vartime() const {
        // int ret = 1;
        // if(!fe25519_iszero(&p->x)) ret = 0;
        // if(!fe25519_iseq_vartime(&p->y, &p->z)) ret = 0;
        // return ret;
        return FT::AND(m_x.iszero(), m_y.iseq_vartime(m_z));
    }

    // computes [s1]p1 + [s2]p2
    void double_scalarmult_vartime(const ge25519& p1,
                                   sc25519<T, U, B, FT, FU, NS>& s1,
                                   const ge25519& p2,
                                   const sc25519<T, U, B, FT, FU, NS>& s2) {
        // ge25519_p1p1 tp1p1;
        ge25519 tp1p1;

        // ge25519_p3 pre[16];
        std::array<ge25519, 16> pre;

        // unsigned char b[127];
        std::array<U, 127> b;

        // precomputation
        // s2 s1

        // setneutral(pre);
        // 00 00
        pre[0].setneutral();

        // pre[1] = *p1;
        // 00 01
        pre[1] = p1;

        // dbl_p1p1(&tp1p1,(ge25519_p2 *)p1);
        // p1p1_to_p3( &pre[2], &tp1p1);
        // 00 10
        tp1p1.dbl_p1p1(p1);
        pre[2].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[1], &pre[2]);
        // p1p1_to_p3( &pre[3], &tp1p1);
        // 00 11
        tp1p1.add_p1p1(pre[1], pre[2]);
        pre[3].p1p1_to_p3(tp1p1);

        // pre[4] = *p2;
        // 01 00
        pre[4] = p2;

        // add_p1p1(&tp1p1,&pre[1], &pre[4]);
        // p1p1_to_p3( &pre[5], &tp1p1);
        // 01 01
        tp1p1.add_p1p1(pre[1], pre[4]);
        pre[5].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[2], &pre[4]);
        // p1p1_to_p3( &pre[6], &tp1p1);
        // 01 10
        tp1p1.add_p1p1(pre[2], pre[4]);
        pre[6].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[3], &pre[4]);
        // p1p1_to_p3( &pre[7], &tp1p1);
        // 01 11
        tp1p1.add_p1p1(pre[3], pre[4]);
        pre[7].p1p1_to_p3(tp1p1);

        // dbl_p1p1(&tp1p1,(ge25519_p2 *)p2);
        // p1p1_to_p3( &pre[8], &tp1p1);
        // 10 00
        tp1p1.dbl_p1p1(p2);
        pre[8].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[1], &pre[8]);
        // p1p1_to_p3( &pre[9], &tp1p1);
        // 10 01
        tp1p1.add_p1p1(pre[1], pre[8]);
        pre[9].p1p1_to_p3(tp1p1);

        // dbl_p1p1(&tp1p1,(ge25519_p2 *)&pre[5]);
        // p1p1_to_p3(&pre[10], &tp1p1);
        // 10 10
        tp1p1.dbl_p1p1(pre[5]);
        pre[10].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[3], &pre[8]);
        // p1p1_to_p3(&pre[11], &tp1p1);
        // 10 11
        tp1p1.add_p1p1(pre[3], pre[8]);
        pre[11].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[4], &pre[8]);
        // p1p1_to_p3(&pre[12], &tp1p1);
        // 11 00
        tp1p1.add_p1p1(pre[4], pre[8]);
        pre[12].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[1],&pre[12]);
        // p1p1_to_p3(&pre[13], &tp1p1);
        // 11 01
        tp1p1.add_p1p1(pre[1], pre[12]);
        pre[13].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[2],&pre[12]);
        // p1p1_to_p3(&pre[14], &tp1p1);
        // 11 10
        tp1p1.add_p1p1(pre[2], pre[12]);
        pre[14].p1p1_to_p3(tp1p1);

        // add_p1p1(&tp1p1,&pre[3],&pre[12]);
        // p1p1_to_p3(&pre[15], &tp1p1);
        // 11 11
        tp1p1.add_p1p1(pre[3], pre[12]);
        pre[15].p1p1_to_p3(tp1p1);

        // sc25519_2interleave2(b,s1,s2);
        s1.interleave2(b, s2);

        // scalar multiplication

        // *r = pre[b[126]];
        subscript(pre, b[126]);

        for (int i = 125; i >= 0; --i) {
            // dbl_p1p1(&tp1p1, (ge25519_p2 *)r);
            tp1p1.dbl_p1p1(*this);

            // p1p1_to_p2((ge25519_p2 *) r, &tp1p1);
            p1p1_to_p2(tp1p1);

            // dbl_p1p1(&tp1p1, (ge25519_p2 *)r);
            tp1p1.dbl_p1p1(*this);

            // if(b[i]!=0)
            // {
            const B tmp_b = b[i] != FU::constant(0);

            //   p1p1_to_p3(r, &tp1p1);
            ge25519 tmp_r(*this);
            tmp_r.p1p1_to_p3(tp1p1);

            //   add_p1p1(&tp1p1, r, &pre[b[i]]);
            ge25519 tmp_tp1p1(tp1p1), tmp_q;
            tmp_q.subscript(pre, b[i]);
            tmp_tp1p1.add_p1p1(tmp_r, tmp_q);

            // }
            for (std::size_t i = 0; i < 32; ++i) {
                m_x[i] = FT::ternary(tmp_b, tmp_r.m_x[i], m_x[i]);
                m_y[i] = FT::ternary(tmp_b, tmp_r.m_y[i], m_y[i]);
                m_z[i] = FT::ternary(tmp_b, tmp_r.m_z[i], m_z[i]);
                m_t[i] = FT::ternary(tmp_b, tmp_r.m_t[i], m_t[i]);

                tp1p1.m_x[i] = FT::ternary(tmp_b, tmp_tp1p1.m_x[i], tp1p1.m_x[i]);
                tp1p1.m_y[i] = FT::ternary(tmp_b, tmp_tp1p1.m_y[i], tp1p1.m_y[i]);
                tp1p1.m_z[i] = FT::ternary(tmp_b, tmp_tp1p1.m_z[i], tp1p1.m_z[i]);
                tp1p1.m_t[i] = FT::ternary(tmp_b, tmp_tp1p1.m_t[i], tp1p1.m_t[i]);
            }

            // if(i != 0) p1p1_to_p2((ge25519_p2 *)r, &tp1p1);
            // else p1p1_to_p3(r, &tp1p1);
            if (i != 0)
                p1p1_to_p2(tp1p1);
            else
                p1p1_to_p3(tp1p1);
        }
    }

    void scalarmult_base(sc25519<T, U, B, FT, FU, NS>& s) {
        // signed char b[85];
        // sc25519_window3(b,s);
        std::array<U, 85> b;
        s.window3(b);

        // choose_t((ge25519_aff *)r, 0, b[0]);
        choose_t(0, b[0]);

        // fe25519_setone(&r->z);
        m_z.setone();

        // fe25519_mul(&r->t, &r->x, &r->y);
        m_t.mul(m_x, m_y);

        for (std::size_t i = 1; i < 85; ++i) {
            ge25519_aff<T, U, B, FT, FU, NS> t;

            // choose_t(&t, (unsigned long long) i, b[i]);
            t.choose_t(i, b[i]);

            // ge25519_mixadd2(r, &t);
            mixadd2(t);
        }
    }

    // Packed coordinates of the base point
    static const ge25519& base() {
        static const ge25519 a(
            // x
            { 0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
              0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
              0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
              0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21 },

            // y
            { 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 },

            // z
            { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

            // t
            { 0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D,
              0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20,
              0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66,
              0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67 });

        return a;
    }

private:
    void p1p1_to_p2(const ge25519& p) {
        // fe25519_mul(&r->x, &p->x, &p->t);
        m_x.mul(p.m_x, p.m_t);

        // fe25519_mul(&r->y, &p->y, &p->z);
        m_y.mul(p.m_y, p.m_z);

        // fe25519_mul(&r->z, &p->z, &p->t);
        m_z.mul(p.m_z, p.m_t);
    }

    void p1p1_to_p3(const ge25519& p) {
        // p1p1_to_p2((ge25519_p2 *)r, p);
        p1p1_to_p2(p);

        // fe25519_mul(&r->t, &p->x, &p->y);
        m_t.mul(p.m_x, p.m_y);
    }

    void mixadd2(const ge25519_aff<T, U, B, FT, FU, NS>& q) {
        // 2*d
        static const fe25519<T, U, B, FT, NS> ge25519_ec2d({
            0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB,
            0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00, 
            0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19,
            0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24 });

        fe25519<T, U, B, FT, NS> a, b, t1, t2, c, d, e, f, g, h, qt;

        // fe25519_mul(&qt, &q->x, &q->y);
        qt.mul(q.x(), q.y());

        // fe25519_sub(&a, &r->y, &r->x); /* A = (Y1-X1)*(Y2-X2) */
        a.sub(m_y, m_x);

        // fe25519_add(&b, &r->y, &r->x); /* B = (Y1+X1)*(Y2+X2) */
        b.add(m_y, m_x);

        // fe25519_sub(&t1, &q->y, &q->x);
        t1.sub(q.y(), q.x());

        // fe25519_add(&t2, &q->y, &q->x);
        t2.add(q.y(), q.x());

        // fe25519_mul(&a, &a, &t1);
        a.mul(a, t1);

        // fe25519_mul(&b, &b, &t2);
        b.mul(b, t2);

        // fe25519_sub(&e, &b, &a); /* E = B-A */
        e.sub(b, a);

        // fe25519_add(&h, &b, &a); /* H = B+A */
        h.add(b, a);

        // fe25519_mul(&c, &r->t, &qt); /* C = T1*k*T2 */
        c.mul(m_t, qt);

        // fe25519_mul(&c, &c, &ge25519_ec2d);
        c.mul(c, ge25519_ec2d);

        // fe25519_add(&d, &r->z, &r->z); /* D = Z1*2 */
        d.add(m_z, m_z);

        // fe25519_sub(&f, &d, &c); /* F = D-C */
        f.sub(d, c);

        // fe25519_add(&g, &d, &c); /* G = D+C */
        g.add(d, c);

        // fe25519_mul(&r->x, &e, &f);
        m_x.mul(e, f);

        // fe25519_mul(&r->y, &h, &g);
        m_y.mul(h, g);

        // fe25519_mul(&r->z, &g, &f);
        m_z.mul(g, f);

        // fe25519_mul(&r->t, &e, &h);
        m_t.mul(e, h);
    }

    void add_p1p1(const ge25519& p, const ge25519& q) {
        // 2*d
        static const fe25519<T, U, B, FT, NS> ge25519_ec2d({
            0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB,
            0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00, 
            0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19,
            0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24 });

        fe25519<T, U, B, FT, NS> a, b, c, d, t;

        // fe25519_sub(&a, &p->y, &p->x); /* A = (Y1-X1)*(Y2-X2) */
        a.sub(p.m_y, p.m_x);

        // fe25519_sub(&t, &q->y, &q->x);
        t.sub(q.m_y, q.m_x);

        // fe25519_mul(&a, &a, &t);
        a.mul(a, t);

        // fe25519_add(&b, &p->x, &p->y); /* B = (Y1+X1)*(Y2+X2) */
        b.add(p.m_x, p.m_y);

        // fe25519_add(&t, &q->x, &q->y);
        t.add(q.m_x, q.m_y);

        // fe25519_mul(&b, &b, &t);
        b.mul(b, t);

        // fe25519_mul(&c, &p->t, &q->t); /* C = T1*k*T2 */
        c.mul(p.m_t, q.m_t);

        // fe25519_mul(&c, &c, &ge25519_ec2d);
        c.mul(c, ge25519_ec2d);

        // fe25519_mul(&d, &p->z, &q->z); /* D = Z1*2*Z2 */
        d.mul(p.m_z, q.m_z);

        // fe25519_add(&d, &d, &d);
        d.add(d, d);

        // fe25519_sub(&r->x, &b, &a); /* E = B-A */
        m_x.sub(b, a);

        // fe25519_sub(&r->t, &d, &c); /* F = D-C */
        m_t.sub(d, c);

        // fe25519_add(&r->z, &d, &c); /* G = D+C */
        m_z.add(d, c);

        // fe25519_add(&r->y, &b, &a); /* H = B+A */
        m_y.add(b, a);
    }

    // See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
    void dbl_p1p1(const ge25519& p) {
        fe25519<T, U, B, FT, NS> a, b, c, d;

        // fe25519_square(&a, &p->x);
        a.square(p.m_x);

        // fe25519_square(&b, &p->y);
        b.square(p.m_y);

        // fe25519_square(&c, &p->z);
        c.square(p.m_z);

        // fe25519_add(&c, &c, &c);
        c.add(c, c);

        // fe25519_neg(&d, &a);
        d.neg(a);

        // fe25519_add(&r->x, &p->x, &p->y);
        m_x.add(p.m_x, p.m_y);

        // fe25519_square(&r->x, &r->x);
        m_x.square(m_x);

        // fe25519_sub(&r->x, &r->x, &a);
        m_x.sub(m_x, a);

        // fe25519_sub(&r->x, &r->x, &b);
        m_x.sub(m_x, b);

        // fe25519_add(&r->z, &d, &b);
        m_z.add(d, b);

        // fe25519_sub(&r->t, &r->z, &c);
        m_t.sub(m_z, c);

        // fe25519_sub(&r->y, &d, &b);
        m_y.sub(d, b);
    }

    void setneutral() {
        // fe25519_setzero(&r->x);
        m_x.setzero();

        // fe25519_setone(&r->y);
        m_y.setone();

        // fe25519_setone(&r->z);
        m_z.setone();

        // fe25519_setzero(&r->t);
        m_t.setzero();
    }

    void choose_t(const std::size_t pos, const U& b) {
        ge25519_aff<T, U, B, FT, FU, NS> a(m_x, m_y);
        a.choose_t(pos, b);
        m_x = a.x();
        m_y = a.y();
    }

    template <std::size_t N>
    void subscript(const std::array<ge25519, N>& pre, const U& idx) {
        for (std::size_t j = 0; j < 32; ++j) {
            std::array<T, N> ax, ay, az, at;

            for (std::size_t i = 0; i < N; ++i) {
                ax[i] = pre[i].m_x[j];
                ay[i] = pre[i].m_y[j];
                az[i] = pre[i].m_z[j];
                at[i] = pre[i].m_t[j];
            }

            m_x[j] = FT::arraysubscript(ax, idx);
            m_y[j] = FT::arraysubscript(ay, idx);
            m_z[j] = FT::arraysubscript(az, idx);
            m_t[j] = FT::arraysubscript(at, idx);
        }
    }

    fe25519<T, U, B, FT, NS> m_x, m_y, m_z, m_t;
};

} // namespace cryptl

#endif
