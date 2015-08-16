#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include <cryptl/ASCII_Hex.hpp>
#include <cryptl/ED25519.hpp>
#include <cryptl/NS_cryptl.hpp>

using namespace cryptl;
using namespace std;

void printUsage(const char* exeName) {
    const string
        SK = " -s secret_key_in_hex",
        PK = " -p public_key_in_hex",
        M = " -m message_in_hex",
        R = " -R signature_R_in_hex",
        S = " -S signature_S_in_hex";

    cout << "public key:   " << exeName << SK << endl;
    cout << "sign message: " << exeName << SK << M << endl;
    cout << "open message: " << exeName << PK << M << R << S << endl;
}

int main(int argc, char *argv[])
{
    array<uint8_t, 32> sk, pk, R, S;
    vector<uint8_t> m;
    bool bs = false, bp = false, bm = false, bR = false, bS = false;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "s:p:m:R:S:"))) {
        switch (opt) {

        case ('s') : // secret key
            if (!asciiHexToArray(optarg, sk)) {
                cerr << "error: secret key in hex: " << optarg << endl;
                exit(EXIT_FAILURE);
            }
            bs = true;
            break;

        case ('p') : // public key
            if (!asciiHexToArray(optarg, pk)) {
                cerr << "error: public key in hex: " << optarg << endl;
                exit(EXIT_FAILURE);
            }
            bp = true;
            break;

        case ('m') : // message
            if (!asciiHexToVector(optarg, m)) {
                cerr << "error: message in hex: " << optarg << endl;
                exit(EXIT_FAILURE);
            }
            bm = true;
            break;

        case ('R') : // signature R
            if (!asciiHexToArray(optarg, R)) {
                cerr << "error: signature R in hex: " << optarg << endl;
                exit(EXIT_FAILURE);
            }
            bR = true;
            break;

        case ('S') : // signature S
            if (!asciiHexToArray(optarg, S)) {
                cerr << "error: signature S in hex: " << optarg << endl;
                exit(EXIT_FAILURE);
            }
            bS = true;
            break;
        }
    }

    if (bs) {
        if (!bp && !bR && !bS) {
            // calculate public key
            ED25519::keypair(pk, sk);

            if (bm) {
                // sign message
                ED25519::sign(R, S, m, pk, sk);

                // output signature
                cout << "R: " << asciiHex(R) << endl
                     << "S: " << asciiHex(S) << endl;

                return EXIT_SUCCESS;

            } else {
                // public key
                cout << "pk: " << asciiHex(pk) << endl;

                return EXIT_SUCCESS;
            }
        }

    } else {
        if (bR && bS && bm && bp) {
            // open message
            cout << (ED25519::open(R, S, m, pk) ? "OK" : "FAIL") << endl;

            return EXIT_SUCCESS;
        }
    }

    printUsage(argv[0]);

    exit(EXIT_FAILURE);
}
