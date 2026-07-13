#include "volta_chacha8_fp.cuh"

#include <cuda_runtime.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using volta::chacha8_fp::Fp2;
using volta::chacha8_fp::Key;
using volta::chacha8_fp::Stream;

#define CUDA_CHECK(call)                                                                    \
    do {                                                                                    \
        const cudaError_t error__ = (call);                                                 \
        if (error__ != cudaSuccess) {                                                       \
            std::cerr << #call << ": " << cudaGetErrorString(error__) << "\n";           \
            std::exit(2);                                                                   \
        }                                                                                   \
    } while (0)

constexpr const char* kDefaultSeedHex =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

enum class Mode { Fp, Fp2 };

struct Args {
    Mode mode = Mode::Fp;
    std::uint8_t seed[32]{};
    std::string seed_hex;
    std::uint64_t base_domain = UINT64_C(0x0123456789ABCDEF);
    std::uint64_t rows = 3;
    std::uint64_t count = 10;
};

__global__ void generate_fp_rows(
    Key key,
    std::uint64_t base_domain,
    std::uint64_t rows,
    std::uint64_t count,
    std::uint64_t* output) {
    const std::uint64_t first =
        static_cast<std::uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const std::uint64_t stride = static_cast<std::uint64_t>(gridDim.x) * blockDim.x;
    for (std::uint64_t row = first; row < rows; row += stride) {
        Stream stream(key, base_domain + row);
        const std::uint64_t offset = row * count;
        for (std::uint64_t column = 0; column < count; ++column) {
            output[offset + column] = stream.next_fp();
        }
    }
}

__global__ void generate_fp2_rows(
    Key key,
    std::uint64_t base_domain,
    std::uint64_t rows,
    std::uint64_t count,
    Fp2* output) {
    const std::uint64_t first =
        static_cast<std::uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const std::uint64_t stride = static_cast<std::uint64_t>(gridDim.x) * blockDim.x;
    for (std::uint64_t row = first; row < rows; row += stride) {
        Stream stream(key, base_domain + row);
        const std::uint64_t offset = row * count;
        for (std::uint64_t column = 0; column < count; ++column) {
            // c0 and c1 are consecutive accepted Fp values from this row's
            // stream, exactly like FpStream::next_fp2.
            output[offset + column] = stream.next_fp2();
        }
    }
}

std::string usage(const char* program) {
    std::ostringstream out;
    out << "usage: " << program
        << " [--mode fp|fp2] [--seed-hex 64_HEX] [--base-domain U64]"
           " [--rows U64] [--count U64]\n"
        << "defaults: --mode fp --seed-hex " << kDefaultSeedHex
        << " --base-domain 0x0123456789abcdef --rows 3 --count 10";
    return out.str();
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void parse_seed(const std::string& input, std::uint8_t seed[32], std::string& normalized) {
    const std::string value =
        input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
        ? input.substr(2)
        : input;
    if (value.size() != 64) {
        throw std::runtime_error(
            "seed must contain exactly 64 hex digits, got " + std::to_string(value.size()));
    }
    normalized.clear();
    normalized.reserve(64);
    constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = hex_nibble(value[2 * i]);
        const int lo = hex_nibble(value[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("invalid seed hex at digit " + std::to_string(2 * i));
        }
        seed[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        normalized.push_back(kHex[hi]);
        normalized.push_back(kHex[lo]);
    }
}

std::uint64_t parse_u64(const std::string& value, const char* name) {
    if (value.empty() || value[0] == '-') {
        throw std::runtime_error(std::string("invalid ") + name + " value " + value);
    }
    const bool hex =
        value.size() >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X');
    const char* begin = value.c_str() + (hex ? 2 : 0);
    if (*begin == '\0') {
        throw std::runtime_error(std::string("invalid ") + name + " value " + value);
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(begin, &end, hex ? 16 : 10);
    if (errno == ERANGE || end == begin || *end != '\0') {
        throw std::runtime_error(std::string("invalid ") + name + " value " + value);
    }
    return static_cast<std::uint64_t>(parsed);
}

Args parse_args(int argc, char** argv) {
    Args args;
    parse_seed(kDefaultSeedHex, args.seed, args.seed_hex);
    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--help" || flag == "-h") {
            std::cout << usage(argv[0]) << "\n";
            std::exit(0);
        }
        if (i + 1 == argc) throw std::runtime_error("missing value after " + flag);
        const std::string value = argv[++i];
        if (flag == "--mode") {
            if (value == "fp") {
                args.mode = Mode::Fp;
            } else if (value == "fp2") {
                args.mode = Mode::Fp2;
            } else {
                throw std::runtime_error("invalid mode " + value + "; expected fp or fp2");
            }
        } else if (flag == "--seed-hex") {
            parse_seed(value, args.seed, args.seed_hex);
        } else if (flag == "--base-domain") {
            args.base_domain = parse_u64(value, "base domain");
        } else if (flag == "--rows") {
            args.rows = parse_u64(value, "rows");
        } else if (flag == "--count") {
            args.count = parse_u64(value, "count");
        } else {
            throw std::runtime_error("unknown argument " + flag);
        }
    }
    if (args.rows != 0 && args.rows - 1 > std::numeric_limits<std::uint64_t>::max() - args.base_domain) {
        throw std::runtime_error("base_domain + row overflows u64");
    }
    if (args.count != 0 && args.rows > std::numeric_limits<std::uint64_t>::max() / args.count) {
        throw std::runtime_error("rows * count overflows u64");
    }
    return args;
}

std::size_t element_count(const Args& args) {
    const std::uint64_t count = args.rows * args.count;
    if (count > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("rows * count exceeds host size_t");
    }
    return static_cast<std::size_t>(count);
}

std::string hex_u64(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

template <typename Value, typename EmitValue>
void emit_json(const Args& args, const std::vector<Value>& values, EmitValue emit_value) {
    std::cout << "{\n"
              << "  \"schema\":\"p7b-chacha8-fp-diff-v1\",\n"
              << "  \"mode\":\"" << (args.mode == Mode::Fp ? "fp" : "fp2") << "\",\n"
              << "  \"seed_hex\":\"" << args.seed_hex << "\",\n"
              << "  \"base_domain\":\"" << hex_u64(args.base_domain) << "\",\n"
              << "  \"rows\":" << args.rows << ",\n"
              << "  \"count\":" << args.count << ",\n"
              << "  \"values\":[\n";
    for (std::uint64_t row = 0; row < args.rows; ++row) {
        std::cout << "    [";
        for (std::uint64_t column = 0; column < args.count; ++column) {
            if (column != 0) std::cout << ',';
            emit_value(values[static_cast<std::size_t>(row * args.count + column)]);
        }
        std::cout << ']' << (row + 1 == args.rows ? "\n" : ",\n");
    }
    std::cout << "  ]\n}\n";
}

int launch(const Args& args) {
    static_assert(sizeof(Fp2) == 16, "Fp2 output must be two packed u64 values");
    const std::size_t elements = element_count(args);
    if (elements == 0) {
        if (args.mode == Mode::Fp) {
            emit_json(args, std::vector<std::uint64_t>{}, [](std::uint64_t value) {
                std::cout << '\"' << hex_u64(value) << '\"';
            });
        } else {
            emit_json(args, std::vector<Fp2>{}, [](Fp2 value) {
                std::cout << "[\"" << hex_u64(value.c0) << "\",\"" << hex_u64(value.c1)
                          << "\"]";
            });
        }
        return 0;
    }

    constexpr unsigned int kThreads = 128;
    const std::uint64_t needed_blocks = (args.rows + kThreads - 1) / kThreads;
    const unsigned int blocks = static_cast<unsigned int>(
        needed_blocks < UINT64_C(65535) ? needed_blocks : UINT64_C(65535));
    const Key key = volta::chacha8_fp::key_from_seed(args.seed);

    if (args.mode == Mode::Fp) {
        if (elements > std::numeric_limits<std::size_t>::max() / sizeof(std::uint64_t)) {
            throw std::runtime_error("Fp output byte count overflows size_t");
        }
        std::uint64_t* device = nullptr;
        CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device), elements * sizeof(*device)));
        generate_fp_rows<<<blocks, kThreads>>>(
            key, args.base_domain, args.rows, args.count, device);
        CUDA_CHECK(cudaGetLastError());
        std::vector<std::uint64_t> host(elements);
        CUDA_CHECK(cudaMemcpy(
            host.data(), device, elements * sizeof(*device), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaFree(device));
        emit_json(args, host, [](std::uint64_t value) {
            std::cout << '\"' << hex_u64(value) << '\"';
        });
    } else {
        if (elements > std::numeric_limits<std::size_t>::max() / sizeof(Fp2)) {
            throw std::runtime_error("Fp2 output byte count overflows size_t");
        }
        Fp2* device = nullptr;
        CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device), elements * sizeof(*device)));
        generate_fp2_rows<<<blocks, kThreads>>>(
            key, args.base_domain, args.rows, args.count, device);
        CUDA_CHECK(cudaGetLastError());
        std::vector<Fp2> host(elements);
        CUDA_CHECK(cudaMemcpy(host.data(), device, elements * sizeof(*device), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaFree(device));
        emit_json(args, host, [](Fp2 value) {
            std::cout << "[\"" << hex_u64(value.c0) << "\",\"" << hex_u64(value.c1)
                      << "\"]";
        });
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        // The seed here is a shared mask/correlation seed, never a verifier
        // challenge or verifier-only key.
        return launch(parse_args(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n" << usage(argv[0]) << "\n";
        return 2;
    }
}
