#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <iomanip>
#include <random>
#include <string>
#include <unordered_map>
#include <cmath>
#include <cstdint>
#include <cstddef>
#include <fstream>

using namespace std;
using namespace CryptoPP;
using namespace CryptoPP::Weak;
using u8 = CryptoPP::byte;

mt19937 rng(random_device{}());

const size_t N = 100;
uint64_t atack11_[N];
uint64_t atack12_[N];
uint64_t atack21_[N];
uint64_t atack22_[N];

double emp_mean(const uint64_t* data, size_t n)
{
    if (n == 0) return 0.0;
    long double sum = 0;
    for (size_t i = 0; i < n; i++)
        sum += data[i];
    return static_cast<double>(sum / n);
}

double emp_variance(const uint64_t* data, size_t n)
{
    if (n < 2) return 0.0;
    long double m = emp_mean(data, n);
    long double sum = 0;
    for (size_t i = 0; i < n; i++)
    {
        long double d = static_cast<long double>(data[i]) - m;
        sum += d * d;
    }
    return static_cast<double>(sum / (n - 1));
}

struct ConfInterval
{
    double low;
    double high;
};

ConfInterval conf_interval(const uint64_t* data, size_t n, double z = 1.96)
{
    double m = emp_mean(data, n);
    double delta = z * sqrt(emp_variance(data, n) / n);
    return { m - delta, m + delta };
}

void print_stats(const string& title, const uint64_t* data, size_t n, double z = 1.96)
{
    double m = emp_mean(data, n);
    double v = emp_variance(data, n);
    ConfInterval ci = conf_interval(data, n, z);

    cout << fixed << setprecision(2);
    cout << "\n=== " << title << " ===\n";
    cout << "Mathematical expectation: " << m << "\n";
    cout << "Variance:                 " << v << "\n";
    cout << "Standard deviation:       " << sqrt(v) << "\n";
    cout << "Confidence interval:      [" << ci.low << "; " << ci.high << "]\n";
    cout.unsetf(ios::fixed);
}

void save_csv(const string& filename)
{
    ofstream f(filename);
    f << "run,atack11,atack12,atack21,atack22\n";
    for (size_t k = 0; k < N; k++)
        f << k + 1 << ',' << atack11_[k] << ',' << atack12_[k] << ','
        << atack21_[k] << ',' << atack22_[k] << '\n';
    cout << "\nResults saved to " << filename << "\n";
}

string random_chenge(string& temp)
{
    uniform_int_distribution<int> dist(0, temp.size() - 1);
    int pos = dist(rng);
    char c;
    do
    {
        uniform_int_distribution<int> dist(33, 255);
        c = static_cast<char>(dist(rng));
    } while (c == temp[pos]);
    temp[pos] = c;
    return temp;
}

const uint64_t PRINT_FIRST = 30;

string md5_hex(const string& msg)
{
    MD5 hash;
    string rez;
    StringSource ss(msg, true, new HashFilter(hash, new HexEncoder(new StringSink(rez), false)));
    return rez;
}

string digest_hex(const u8* out, size_t len)
{
    string rez;
    StringSource ss(out, len, true, new HexEncoder(new StringSink(rez), false));
    return rez;
}

void print_step(uint64_t i, const string& msg, const string& hex)
{
    cout << "  [" << setw(2) << i << "] MD5(" << msg << ") = " << hex << "\n";
}

uint64_t atack11(string& name, bool verbose)
{
    string rez = md5_hex(name);
    if (verbose) cout << "First " << PRINT_FIRST << " values:\n";

    string name16 = rez.substr(rez.size() - 4);
    uint64_t i = 0;
    while (true)
    {
        string temp = name + to_string(i);
        string temp_ = md5_hex(temp);
        if (verbose && i < PRINT_FIRST)
            print_step(i, temp, temp_);

        if (temp_.substr(temp_.size() - 4) == name16)
        {
            if (verbose)
            {
                cout << "Last message (last 16 bits match):\n";
                cout << "  [" << i << "] MD5(" << temp << ") = " << temp_ << "\n";
            }
            break;
        }
        i++;
    }
    return i + 1;
}

uint64_t atack12(string& name, bool verbose)
{
    string rez = md5_hex(name);
    if (verbose) cout << "First " << PRINT_FIRST << " values:\n";

    string name16 = rez.substr(rez.size() - 4);
    uint64_t i = 0;
    string temp = name;
    while (true)
    {
        temp = random_chenge(temp);
        string temp_ = md5_hex(temp);
        if (verbose && i < PRINT_FIRST)
            print_step(i, temp, temp_);

        if (temp_.substr(temp_.size() - 4) == name16 && temp != name)
        {
            if (verbose)
            {
                cout << "Last message (last 16 bits match):\n";
                cout << "  [" << i << "] MD5(" << temp << ") = " << temp_ << "\n";
            }
            break;
        }
        i++;
    }
    return i + 1;
}

uint64_t atack21(string& name, bool verbose)
{
    MD5 hash;
    unordered_map<uint32_t, uint64_t> seen;
    seen.reserve(200000);

    if (verbose) cout << "First " << PRINT_FIRST << " values:\n";

    u8 out[MD5::DIGESTSIZE];
    uint64_t i = 0;
    while (true)
    {
        string temp = name + to_string(i);
        hash.CalculateDigest(out, (const u8*)temp.data(), temp.size());
        if (verbose && i < PRINT_FIRST)
            print_step(i, temp, digest_hex(out, sizeof(out)));

        uint32_t tail = (uint32_t(out[12]) << 24) | (uint32_t(out[13]) << 16) | (uint32_t(out[14]) << 8) | uint32_t(out[15]);

        auto it = seen.find(tail);
        if (it != seen.end())
        {
            string prev = name + to_string(it->second);
            if (verbose)
            {
                cout << "Collision (last 32 bits):\n";
                cout << "  [" << it->second << "] MD5(" << prev << ") = " << md5_hex(prev) << "\n";
                cout << "  [" << i << "] MD5(" << temp << ") = " << digest_hex(out, sizeof(out)) << "\n";
            }
            break;
        }

        seen[tail] = i;
        i++;
    }
    return i + 1;
}

uint64_t atack22(string& name, bool verbose)
{
    MD5 hash;
    unordered_map<uint32_t, pair<string, uint64_t>> seen;
    seen.reserve(200000);

    if (verbose) cout << "First " << PRINT_FIRST << " values:\n";

    u8 out[MD5::DIGESTSIZE];
    string temp = name;
    uint64_t i = 0;
    while (true)
    {
        temp = random_chenge(temp);
        hash.CalculateDigest(out, (const u8*)temp.data(), temp.size());
        if (verbose && i < PRINT_FIRST)
            print_step(i, temp, digest_hex(out, sizeof(out)));

        uint32_t tail = (uint32_t(out[12]) << 24) | (uint32_t(out[13]) << 16) | (uint32_t(out[14]) << 8) | uint32_t(out[15]);

        auto it = seen.find(tail);
        if (it != seen.end())
        {
            if (it->second.first == temp)
            {
                i++;
                continue;
            }

            const string& prev = it->second.first;
            if (verbose)
            {
                cout << "Collision (last 32 bits):\n";
                cout << "  [" << it->second.second << "] MD5(" << prev << ") = " << md5_hex(prev) << "\n";
                cout << "  [" << i << "] MD5(" << temp << ") = " << digest_hex(out, sizeof(out)) << "\n";
            }
            break;
        }

        seen[tail] = { temp, i };
        i++;
    }
    return i + 1;
}

int main()
{
    string name = "Aghamalian Myron";

    cout << "Chosen message: MD5(" << name << ") = " << md5_hex(name) << "\n";

    for (size_t k = 0; k < N; k++)
    {
        if (k > 0)
            random_chenge(name);

        bool verbose = (k == 0);

        if (verbose) cout << "\n--- Attack 1.1 (second preimage, 16 bit, sequential) ---\n";
        atack11_[k] = atack11(name, verbose);

        if (verbose) cout << "\n--- Attack 1.2 (second preimage, 16 bit, random) ---\n";
        atack12_[k] = atack12(name, verbose);

        if (verbose) cout << "\n--- Attack 2.1 (birthday, 32 bit, sequential) ---\n";
        atack21_[k] = atack21(name, verbose);

        if (verbose) cout << "\n--- Attack 2.2 (birthday, 32 bit, random) ---\n";
        atack22_[k] = atack22(name, verbose);
    }

    cout << "\n\n################ STATISTICS ################\n";
    print_stats("Attack 1.1 (second preimage, 16 bit, sequential)", atack11_, N);
    print_stats("Attack 1.2 (second preimage, 16 bit, random)", atack12_, N);
    print_stats("Attack 2.1 (birthday, 32 bit, sequential)", atack21_, N);
    print_stats("Attack 2.2 (birthday, 32 bit, random)", atack22_, N);

    save_csv("results.csv");

    return 0;
}