#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "cryptl/AES.hpp"
#include "cryptl/ASCII_Hex.hpp"
#include "cryptl/CipherModes.hpp"

using namespace cryptl;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: cat NIST_AESAVS_test_file | "
         << exeName
         << " -b 128|192|256 -m ECB|CBC|OFB|CFB"
         << endl;

    exit(EXIT_FAILURE);
}

template <typename T>
bool runCipher(const string& blockMode,
               const string& key,
               const string& IV,
               const string& inText,
               const string& outText)
{
    // convert hexadecimal key and input text to binary
    typename T::KeyType bkey;
    vector<uint8_t> btext;
    if (!asciiHexToArray(key, bkey) ||
        !asciiHexToVector(inText, btext))
        return false;

    // convert hexadecimal initialization value to binary (except ECB)
    typename T::BlockType bIV;
    if (!IV.empty()) {
        if (!asciiHexToArray(IV, bIV)) return false;
    }

    // compute output text
    vector<uint8_t> eval_text;
    if ("ECB" == blockMode)
        eval_text = ECB(T(), bkey, btext);
    else if ("CBC" == blockMode)
        eval_text = CBC(T(), bkey, bIV, btext);
    else if ("OFB" == blockMode)
        eval_text = OFB(T(), bkey, bIV, btext);
    else if ("CFB" == blockMode)
        eval_text = CFB(T(), bkey, bIV, btext);

    // compare output text and AESAVS test case output
    return outText == asciiHex(eval_text);
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

bool readLoop(const size_t aesBits, const string& blockMode)
{
    bool allOK = true;

    bool encryptMode = false, decryptMode = false;
    string line, count, key, IV, plaintext, ciphertext;
    while (!cin.eof() && getline(cin, line)) {
        // skip empty lines and comments
        if (line.empty() || '#' == line[0])
            continue;

        // encrypt mode
        if (string::npos != line.find("ENCRYPT")) {
            encryptMode = true;
            decryptMode = false;
            continue;
        }

        // decrypt mode
        if (string::npos != line.find("DECRYPT")) {
            encryptMode = false;
            decryptMode = true;
            continue;
        }

        string lhs, rhs;
        if (! readAssignment(line, lhs, rhs))
            continue;

        if ("COUNT" == lhs) {
            // test number
            count = rhs;

        } else if ("KEY" == lhs) {
            // cipher key
            key = rhs;

        } else if ("IV" == lhs) {
            // initialization value
            IV = rhs;

        } else if ("PLAINTEXT" == lhs) {
            // plain text
            plaintext = rhs;

        } else if ("CIPHERTEXT" == lhs) {
            // cipher text
            ciphertext = rhs;
        }

        if (!plaintext.empty() && !ciphertext.empty()) {
            bool result = false;

            if (encryptMode) {
                switch (aesBits) {
                case (128) :
                    result = runCipher<AES128>(blockMode,
                                               key,
                                               IV,
                                               plaintext,
                                               ciphertext);
                    break;
                case (192) :
                    result = runCipher<AES192>(blockMode,
                                               key,
                                               IV,
                                               plaintext,
                                               ciphertext);
                    break;
                case (256) :
                    result = runCipher<AES256>(blockMode,
                                               key,
                                               IV,
                                               plaintext,
                                               ciphertext);
                    break;
                }

            } else if (decryptMode) {
                if ("ECB" == blockMode || "CBC" == blockMode) {
                    switch (aesBits) {
                    case (128) :
                        result = runCipher<UNAES128>(blockMode,
                                                     key,
                                                     IV,
                                                     ciphertext,
                                                     plaintext);
                        break;
                    case (192) :
                        result = runCipher<UNAES192>(blockMode,
                                                     key,
                                                     IV,
                                                     ciphertext,
                                                     plaintext);
                        break;
                    case (256) :
                        result = runCipher<UNAES256>(blockMode,
                                                     key,
                                                     IV,
                                                     ciphertext,
                                                     plaintext);
                        break;
                    }
                } else if ("OFB" == blockMode || "CFB" == blockMode) {
                    switch (aesBits) {
                    case (128) :
                        result = runCipher<AES128>(blockMode,
                                                   key,
                                                   IV,
                                                   ciphertext,
                                                   plaintext);
                        break;
                    case (192) :
                        result = runCipher<AES192>(blockMode,
                                                   key,
                                                   IV,
                                                   ciphertext,
                                                   plaintext);
                        break;
                    case (256) :
                        result = runCipher<AES256>(blockMode,
                                                   key,
                                                   IV,
                                                   ciphertext,
                                                   plaintext);
                        break;
                    }
                }

            } else {
                result = false;
            }

            cout << (result ? "OK" : "FAIL") << " "
                 << count << " " << ciphertext << endl;

            if (!result) allOK = false;

            plaintext.clear();
            ciphertext.clear();
        }
    }

    return allOK;
}

int main(int argc, char *argv[])
{
    size_t aesBits = -1;
    string blockMode;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "b:m:"))) {
        switch (opt) {
        case ('b') :
            {
                stringstream ss(optarg);
                if (!(ss >> aesBits)) {
                    cerr << "error: number of bits " << optarg << endl;
                    exit(EXIT_FAILURE);
                }
            }
            break;
        case ('m') :
            blockMode = optarg;
            if (("ECB" != blockMode) &&
                ("CBC" != blockMode) &&
                ("OFB" != blockMode) &&
                ("CFB" != blockMode)) {
                cerr << "error: cipher block mode " << optarg << endl;
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    if (-1 == aesBits || blockMode.empty()) printUsage(argv[0]);

    if (readLoop(aesBits, blockMode))
        return EXIT_SUCCESS;
    else
        exit(EXIT_FAILURE);
}
