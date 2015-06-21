#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "cryptl/ASCII_Hex.hpp"
#include "cryptl/DataPusher.hpp"
#include "cryptl/Digest.hpp"
#include "cryptl/SHA_1.hpp"
#include "cryptl/SHA_224.hpp"
#include "cryptl/SHA_256.hpp"
#include "cryptl/SHA_384.hpp"
#include "cryptl/SHA_512.hpp"

using namespace cryptl;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: cat NIST_SHAVS_byte_test_vector_file | "
         << exeName
         << " -b 1|224|256|384|512"
         << endl;

    exit(EXIT_FAILURE);
}

// short and long message tests
template <typename T>
bool runHash(const string& msg, const string& MD)
{
    // convert hexadecimal message text to binary
    vector<uint8_t> v;
    if ("00" != msg && !asciiHexToVector(msg, v)) // 00 is null msg
        return false;

    // compute message digest
    const auto eval_digest = digest(T(), v);

    // compare message digest and SHAVS test case MD
    return MD == asciiHex(eval_digest);
}

// used by Monte Carlo tests
class Vec8
{
public:
    Vec8() = default;
    void pushOctet(const uint8_t a) { m_v.push_back(a); }
    const vector<uint8_t>& data() const { return m_v; }

private:
    vector<uint8_t> m_v;
};

// Monte Carlo tests
template <typename T>
bool runMC(const string& prevMD, const string& MD)
{
    // prevMD is message digest input
    vector<typename T::WordType> v0, v1, v2;
    if (!asciiHexToVector(prevMD, v2)) return false;
    v0 = v1 = v2;

    for (size_t i = 3; i < 1003; ++i) {
        // message is concatenation of last three digests
        DataPusher<Vec8> v;
        v.push(v0);
        v.push(v1);
        v.push(v2);

        // compute message digest
        const auto eval_digest = digest(T(), v->data());

        // rotate message digests
        v0 = v1;
        v1 = v2;
        assert(eval_digest.size() == v2.size());
        for (size_t j = 0; j < v2.size(); ++j)
            v2[j] = eval_digest[j];
    }

    // compare final message digest with test case MD
    return MD == asciiHex(v2);
}

bool readAssignment(const string& line, string& lhs, string& rhs)
{
    stringstream ss(line);

    // left hand side
    if (!ss.eof())
        ss >> lhs;

    // should be =
    string op;
    if (!!ss && !ss.eof() && !lhs.empty())
        ss >> op;

    // right hand side
    if (!!ss && !ss.eof() && ("=" == op))
        ss >> rhs;

    // true if lhs and rhs both defined and op is =
    return !!ss && !lhs.empty() && !rhs.empty();
}

bool readLoop(const size_t shaBits)
{
    bool allOK = true;

    string line, count, seed, len, msg, MD;
    while (!cin.eof() && getline(cin, line)) {
        // skip empty lines and comments
        if (line.empty() || '#' == line[0])
            continue;

        string lhs, rhs;
        if (! readAssignment(line, lhs, rhs))
            continue;

        if ("Len" == lhs) {
            // length of message
            len = rhs;

        } else if ("Msg" == lhs) {
            // message
            msg = rhs;

        } else if ("MD" == lhs) {
            // message digest
            MD = rhs;

        } else if ("COUNT" == lhs) {
            // Monte-Carlo mode
            count = rhs;

        } else if ("Seed" == lhs) {
            // Monte-Carlo mode
            seed = rhs;
        }

        if (seed.empty()) {
            // short and long message modes
            if (!len.empty() && !msg.empty() && !MD.empty()) {
                bool result = false;

                switch (shaBits) {
                case (1) : result = runHash<SHA1>(msg, MD); break;
                case (224) : result = runHash<SHA224>(msg, MD); break;
                case (256) : result = runHash<SHA256>(msg, MD); break;
                case (384) : result = runHash<SHA384>(msg, MD); break;
                case (512) : result = runHash<SHA512>(msg, MD); break;
                }

                cout << (result ? "OK" : "FAIL") << " "
                     << len << " " << MD << endl;

                if (!result) allOK = false;

                len.clear();
                msg.clear();
                MD.clear();
            }

        } else {
            // Monte-Carlo mode
            if (!MD.empty()) {
                bool result = false;

                switch (shaBits) {
                case (1) : result = runMC<SHA1>(seed, MD); break;
                case (224) : result = runMC<SHA224>(seed, MD); break;
                case (256) : result = runMC<SHA256>(seed, MD); break;
                case (384) : result = runMC<SHA384>(seed, MD); break;
                case (512) : result = runMC<SHA512>(seed, MD); break;
                }

                cout << (result ? "OK" : "FAIL") << " "
                     << count << " " << seed << " " << MD << endl;

                if (!result) allOK = false;

                seed = MD;
                MD.clear();
            }
        }
    }

    return allOK;
}

int main(int argc, char *argv[])
{
    size_t shaBits = -1;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "b:"))) {
        switch (opt) {
        case ('b') :
            {
                stringstream ss(optarg);
                if (!(ss >> shaBits) || ((1 != shaBits) &&
                                         (224 != shaBits) &&
                                         (256 != shaBits) &&
                                         (384 != shaBits) &&
                                         (512 != shaBits))) {
                    cerr << "error: number of bits " << optarg << endl;
                    exit(EXIT_FAILURE);
                }
            }
            break;
        }
    }

    if (-1 == shaBits) printUsage(argv[0]);

    if (readLoop(shaBits))
        return EXIT_SUCCESS;
    else
        exit(EXIT_FAILURE);
}
