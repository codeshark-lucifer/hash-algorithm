#include <iostream>
#include <vector>
#include <bitset>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <cstring>

using namespace std;

#define RESET "\033[0m"
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define CYAN "\033[1;36m"

// --- SHA-256 Constants and Functions (unchanged) ---

uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

vector<vector<uint8_t>> preprocess(const string &input)
{
    vector<uint8_t> bytes(input.begin(), input.end());
    uint64_t bitLength = bytes.size() * 8;

    bytes.push_back(0x80);
    while ((bytes.size() * 8) % 512 != 448)
    {
        bytes.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i)
    {
        bytes.push_back((bitLength >> (i * 8)) & 0xFF);
    }

    vector<vector<uint8_t>> blocks;
    for (size_t i = 0; i < bytes.size(); i += 64)
    {
        blocks.emplace_back(bytes.begin() + i, bytes.begin() + i + 64);
    }
    return blocks;
}

string sha256(const string &input)
{
    vector<vector<uint8_t>> blocks = preprocess(input);
    uint32_t h[8];
    copy(begin(H), end(H), h);

    for (const auto &block : blocks)
    {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (block[i * 4] << 24) |
                   (block[i * 4 + 1] << 16) |
                   (block[i * 4 + 2] << 8) |
                   (block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];

        for (int i = 0; i < 64; ++i)
        {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    stringstream ss;
    for (int i = 0; i < 8; ++i)
    {
        ss << hex << setw(8) << setfill('0') << h[i];
    }
    return ss.str();
}

// --- MD5 implementation (simplified) ---

typedef uint32_t UINT4;

struct MD5_CTX
{
    UINT4 state[4];
    UINT4 count[2];
    unsigned char buffer[64];
};

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, const unsigned char *input, size_t inputLen);
void MD5Final(unsigned char digest[16], MD5_CTX *context);

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

inline UINT4 F(UINT4 x, UINT4 y, UINT4 z) { return (x & y) | (~x & z); }
inline UINT4 G(UINT4 x, UINT4 y, UINT4 z) { return (x & z) | (y & ~z); }
inline UINT4 Hmd5(UINT4 x, UINT4 y, UINT4 z) { return x ^ y ^ z; }
inline UINT4 I(UINT4 x, UINT4 y, UINT4 z) { return y ^ (x | ~z); }
inline UINT4 rotate_left(UINT4 x, int n) { return (x << n) | (x >> (32 - n)); }
inline void FF(UINT4 &a, UINT4 b, UINT4 c, UINT4 d, UINT4 x, int s, UINT4 ac)
{
    a += F(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}
inline void GG(UINT4 &a, UINT4 b, UINT4 c, UINT4 d, UINT4 x, int s, UINT4 ac)
{
    a += G(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}
inline void HH(UINT4 &a, UINT4 b, UINT4 c, UINT4 d, UINT4 x, int s, UINT4 ac)
{
    a += Hmd5(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}
inline void II(UINT4 &a, UINT4 b, UINT4 c, UINT4 d, UINT4 x, int s, UINT4 ac)
{
    a += I(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}

void MD5Transform(UINT4 state[4], const unsigned char block[64])
{
    UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    for (int i = 0; i < 16; ++i)
    {
        x[i] = ((UINT4)block[i * 4]) | (((UINT4)block[i * 4 + 1]) << 8) |
               (((UINT4)block[i * 4 + 2]) << 16) | (((UINT4)block[i * 4 + 3]) << 24);
    }

    // Round 1
    FF(a, b, c, d, x[0], S11, 0xd76aa478);
    FF(d, a, b, c, x[1], S12, 0xe8c7b756);
    FF(c, d, a, b, x[2], S13, 0x242070db);
    FF(b, c, d, a, x[3], S14, 0xc1bdceee);
    FF(a, b, c, d, x[4], S11, 0xf57c0faf);
    FF(d, a, b, c, x[5], S12, 0x4787c62a);
    FF(c, d, a, b, x[6], S13, 0xa8304613);
    FF(b, c, d, a, x[7], S14, 0xfd469501);
    FF(a, b, c, d, x[8], S11, 0x698098d8);
    FF(d, a, b, c, x[9], S12, 0x8b44f7af);
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);
    FF(b, c, d, a, x[11], S14, 0x895cd7be);
    FF(a, b, c, d, x[12], S11, 0x6b901122);
    FF(d, a, b, c, x[13], S12, 0xfd987193);
    FF(c, d, a, b, x[14], S13, 0xa679438e);
    FF(b, c, d, a, x[15], S14, 0x49b40821);

    // Round 2
    GG(a, b, c, d, x[1], S21, 0xf61e2562);
    GG(d, a, b, c, x[6], S22, 0xc040b340);
    GG(c, d, a, b, x[11], S23, 0x265e5a51);
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, x[5], S21, 0xd62f105d);
    GG(d, a, b, c, x[10], S22, 0x2441453);
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, x[9], S21, 0x21e1cde6);
    GG(d, a, b, c, x[14], S22, 0xc33707d6);
    GG(c, d, a, b, x[3], S23, 0xf4d50d87);
    GG(b, c, d, a, x[8], S24, 0x455a14ed);
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
    GG(c, d, a, b, x[7], S23, 0x676f02d9);
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, x[5], S31, 0xfffa3942);
    HH(d, a, b, c, x[8], S32, 0x8771f681);
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);
    HH(b, c, d, a, x[14], S34, 0xfde5380c);
    HH(a, b, c, d, x[1], S31, 0xa4beea44);
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);
    HH(d, a, b, c, x[0], S32, 0xeaa127fa);
    HH(c, d, a, b, x[3], S33, 0xd4ef3085);
    HH(b, c, d, a, x[6], S34, 0x4881d05);
    HH(a, b, c, d, x[9], S31, 0xd9d4d039);
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, x[2], S34, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, x[0], S41, 0xf4292244);
    II(d, a, b, c, x[7], S42, 0x432aff97);
    II(c, d, a, b, x[14], S43, 0xab9423a7);
    II(b, c, d, a, x[5], S44, 0xfc93a039);
    II(a, b, c, d, x[12], S41, 0x655b59c3);
    II(d, a, b, c, x[3], S42, 0x8f0ccc92);
    II(c, d, a, b, x[10], S43, 0xffeff47d);
    II(b, c, d, a, x[1], S44, 0x85845dd1);
    II(a, b, c, d, x[8], S41, 0x6fa87e4f);
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, x[6], S43, 0xa3014314);
    II(b, c, d, a, x[13], S44, 0x4e0811a1);
    II(a, b, c, d, x[4], S41, 0xf7537e82);
    II(d, a, b, c, x[11], S42, 0xbd3af235);
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
    II(b, c, d, a, x[9], S44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5Init(MD5_CTX *context)
{
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

void MD5Update(MD5_CTX *context, const unsigned char *input, size_t inputLen)
{
    size_t i, index, partLen;

    index = (size_t)((context->count[0] >> 3) & 0x3F);
    if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
        context->count[1]++;
    context->count[1] += ((UINT4)inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen)
    {
        memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
        {
            MD5Transform(context->state, &input[i]);
        }
        index = 0;
    }
    else
        i = 0;

    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

void MD5Final(unsigned char digest[16], MD5_CTX *context)
{
    unsigned char bits[8];
    size_t index, padLen;

    for (int i = 0; i < 8; i++)
    {
        bits[i] = (unsigned char)((context->count[i >> 2] >> ((i % 4) * 8)) & 0xFF);
    }

    index = (size_t)((context->count[0] >> 3) & 0x3F);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    static const unsigned char PADDING[64] = {0x80};
    MD5Update(context, PADDING, padLen);

    MD5Update(context, bits, 8);
    for (int i = 0; i < 16; i++)
    {
        digest[i] = (unsigned char)((context->state[i >> 2] >> ((i % 4) * 8)) & 0xFF);
    }
}

string md5(const string &input)
{
    MD5_CTX context;
    unsigned char digest[16];
    MD5Init(&context);
    MD5Update(&context, reinterpret_cast<const unsigned char *>(input.c_str()), input.length());
    MD5Final(digest, &context);

    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 16; ++i)
    {
        ss << setw(2) << (int)digest[i];
    }
    return ss.str();
}

// --- Main ---

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        cout << "Usage: " << argv[0] << " <type> [--filter] <message>" << endl;
        return 1;
    }

    string type = argv[1];
    bool filter = false;
    string message;

    if (argc == 4 && string(argv[2]) == "--filter")
    {
        filter = true;
        message = argv[3];
    }
    else if (argc >= 3)
    {
        message = argv[2];
    }

    if (type == "sha256")
    {
        string hash = sha256(message);
        if (filter)
        {
            cout << type << ":" << message << ":" << hash << endl;
        }
        else
        {
            cout << YELLOW << string(hash.length() + 8, '=') << "\n"
                 << RESET
                 << CYAN << "> TYPE: " << RESET << type << "\n"
                 << CYAN << "> TEXT: " << RESET << message << "\n"
                 << CYAN << "> HASH: " << RESET << hash << "\n"
                 << YELLOW << string(hash.length() + 8, '=') << "\n"
                 << RESET;
        }
    }
    else if (type == "md5")
    {
        string hash = md5(message);
        if (filter)
        {
            cout << type << ":" << message << ":" << hash << endl;
        }
        else
        {
            cout << YELLOW << string(hash.length() + 8, '=') << "\n"
                 << RESET
                 << CYAN << "> TYPE: " << RESET << type << "\n"
                 << CYAN << "> TEXT: " << RESET << message << "\n"
                 << CYAN << "> HASH: " << RESET << hash << "\n"
                 << YELLOW << string(hash.length() + 8, '=') << "\n"
                 << RESET;
        }
    }
    else
    {
        cout << "Unsupported type: " << type << endl;
    }

    return 0;
}
