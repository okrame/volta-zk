#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

namespace {

#define CUDA_CHECK(call)                                                                    \
    do {                                                                                    \
        const cudaError_t err__ = (call);                                                   \
        if (err__ != cudaSuccess) {                                                         \
            std::cerr << #call << ": " << cudaGetErrorString(err__) << "\n";               \
            std::exit(2);                                                                   \
        }                                                                                   \
    } while (0)

using Clock = std::chrono::steady_clock;

__global__ void empty_kernel() {}

double elapsed_us(Clock::time_point begin, Clock::time_point end) {
    return std::chrono::duration<double, std::micro>(end - begin).count();
}

struct Samples {
    std::vector<double> values_us;

    void push(double value_us) { values_us.push_back(value_us); }
};

struct SplitSamples {
    Samples enqueue;
    Samples barrier;
    Samples total;
};

struct AllocationSamples {
    Samples allocate;
    Samples release;
    Samples total;
};

double percentile(const std::vector<double>& sorted, double q) {
    if (sorted.empty()) return 0.0;
    const double pos = q * static_cast<double>(sorted.size() - 1);
    const size_t lo = static_cast<size_t>(std::floor(pos));
    const size_t hi = static_cast<size_t>(std::ceil(pos));
    const double weight = pos - static_cast<double>(lo);
    return sorted[lo] * (1.0 - weight) + sorted[hi] * weight;
}

std::string stats_json(const Samples& samples) {
    std::vector<double> sorted = samples.values_us;
    std::sort(sorted.begin(), sorted.end());
    const double median = percentile(sorted, 0.5);
    std::vector<double> deviations;
    deviations.reserve(sorted.size());
    for (double value : sorted) deviations.push_back(std::abs(value - median));
    std::sort(deviations.begin(), deviations.end());
    const double mean = sorted.empty()
        ? 0.0
        : std::accumulate(sorted.begin(), sorted.end(), 0.0) /
            static_cast<double>(sorted.size());
    std::ostringstream out;
    out << std::setprecision(12) << "{\"count\":" << sorted.size()
        << ",\"mean_us\":" << mean
        << ",\"min_us\":" << (sorted.empty() ? 0.0 : sorted.front())
        << ",\"median_us\":" << median
        << ",\"mad_us\":" << percentile(deviations, 0.5)
        << ",\"p95_us\":" << percentile(sorted, 0.95)
        << ",\"max_us\":" << (sorted.empty() ? 0.0 : sorted.back()) << '}';
    return out.str();
}

template <typename F>
Samples measure_for(double target_s, size_t min_samples, F&& operation) {
    Samples samples;
    const auto phase_begin = Clock::now();
    do {
        const auto begin = Clock::now();
        operation();
        const auto end = Clock::now();
        samples.push(elapsed_us(begin, end));
    } while (samples.values_us.size() < min_samples ||
             std::chrono::duration<double>(Clock::now() - phase_begin).count() < target_s);
    return samples;
}

template <typename Launch>
SplitSamples measure_split_for(
    cudaStream_t stream, double target_s, size_t min_samples, Launch&& launch) {
    SplitSamples samples;
    const auto phase_begin = Clock::now();
    do {
        const auto begin = Clock::now();
        launch();
        const auto enqueued = Clock::now();
        CUDA_CHECK(cudaStreamSynchronize(stream));
        const auto completed = Clock::now();
        samples.enqueue.push(elapsed_us(begin, enqueued));
        samples.barrier.push(elapsed_us(enqueued, completed));
        samples.total.push(elapsed_us(begin, completed));
    } while (samples.total.values_us.size() < min_samples ||
             std::chrono::duration<double>(Clock::now() - phase_begin).count() < target_s);
    return samples;
}

AllocationSamples measure_allocations_for(double target_s, size_t min_samples) {
    AllocationSamples samples;
    const auto phase_begin = Clock::now();
    do {
        void* allocation = nullptr;
        const auto begin = Clock::now();
        CUDA_CHECK(cudaMalloc(&allocation, sizeof(uint64_t)));
        const auto allocated = Clock::now();
        CUDA_CHECK(cudaFree(allocation));
        const auto released = Clock::now();
        samples.allocate.push(elapsed_us(begin, allocated));
        samples.release.push(elapsed_us(allocated, released));
        samples.total.push(elapsed_us(begin, released));
    } while (samples.total.values_us.size() < min_samples ||
             std::chrono::duration<double>(Clock::now() - phase_begin).count() < target_s);
    return samples;
}

struct GraphCase {
    size_t kernels = 0;
    cudaGraph_t graph = nullptr;
    cudaGraphExec_t executable = nullptr;
    double build_us = 0.0;
    double instantiate_us = 0.0;
};

GraphCase make_linear_graph(size_t kernels) {
    GraphCase result;
    result.kernels = kernels;
    const auto build_begin = Clock::now();
    CUDA_CHECK(cudaGraphCreate(&result.graph, 0));
    cudaGraphNode_t previous = nullptr;
    cudaKernelNodeParams params{};
    params.func = reinterpret_cast<void*>(empty_kernel);
    params.gridDim = dim3(1, 1, 1);
    params.blockDim = dim3(1, 1, 1);
    params.sharedMemBytes = 0;
    params.kernelParams = nullptr;
    params.extra = nullptr;
    for (size_t i = 0; i < kernels; ++i) {
        cudaGraphNode_t node = nullptr;
        CUDA_CHECK(cudaGraphAddKernelNode(
            &node, result.graph, previous == nullptr ? nullptr : &previous,
            previous == nullptr ? 0 : 1, &params));
        previous = node;
    }
    const auto build_end = Clock::now();
    result.build_us = elapsed_us(build_begin, build_end);
    const auto instantiate_begin = Clock::now();
    CUDA_CHECK(cudaGraphInstantiate(&result.executable, result.graph, nullptr, nullptr, 0));
    const auto instantiate_end = Clock::now();
    result.instantiate_us = elapsed_us(instantiate_begin, instantiate_end);
    return result;
}

std::string json_escape(const char* input) {
    std::ostringstream out;
    for (; *input; ++input) {
        if (*input == '"' || *input == '\\') out << '\\';
        out << *input;
    }
    return out.str();
}

void print_split(const SplitSamples& samples, size_t kernels) {
    std::vector<double> enqueue_per_launch = samples.enqueue.values_us;
    std::vector<double> total_per_launch = samples.total.values_us;
    for (double& value : enqueue_per_launch) value /= static_cast<double>(kernels);
    for (double& value : total_per_launch) value /= static_cast<double>(kernels);
    std::cout << "\"enqueue\":" << stats_json(samples.enqueue)
              << ",\"barrier\":" << stats_json(samples.barrier)
              << ",\"total\":" << stats_json(samples.total)
              << ",\"enqueue_per_launch\":" << stats_json(Samples{enqueue_per_launch})
              << ",\"total_per_launch\":" << stats_json(Samples{total_per_launch});
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " TARGET_SECONDS\n";
        return 2;
    }
    const double target_seconds = std::stod(argv[1]);
    if (!(target_seconds > 0.0)) {
        std::cerr << "TARGET_SECONDS must be positive\n";
        return 2;
    }
    const std::vector<size_t> burst_sizes{1, 8, 64, 512, 4096};
    constexpr size_t timed_cases = 13;  // scalar + 5 direct + D2H + alloc/free + 5 graph.
    const double phase_seconds = target_seconds / static_cast<double>(timed_cases);
    constexpr size_t warmups = 16;
    constexpr size_t min_samples = 7;

    int device = 0;
    CUDA_CHECK(cudaSetDevice(device));
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    int runtime_version = 0, driver_version = 0;
    CUDA_CHECK(cudaRuntimeGetVersion(&runtime_version));
    CUDA_CHECK(cudaDriverGetVersion(&driver_version));
    CUDA_CHECK(cudaFree(nullptr));  // initialize the runtime before timing.
    cudaStream_t stream = nullptr;
    CUDA_CHECK(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking));
    for (size_t i = 0; i < warmups; ++i) {
        empty_kernel<<<1, 1, 0, stream>>>();
        CUDA_CHECK(cudaStreamSynchronize(stream));
    }

    const auto measurement_begin = Clock::now();
    std::cerr << "measuring empty launch + sync\n";
    const Samples launch_sync = measure_for(phase_seconds, min_samples, [stream] {
        empty_kernel<<<1, 1, 0, stream>>>();
        CUDA_CHECK(cudaStreamSynchronize(stream));
    });

    std::vector<SplitSamples> direct;
    direct.reserve(burst_sizes.size());
    for (size_t kernels : burst_sizes) {
        std::cerr << "measuring direct burst N=" << kernels << "\n";
        direct.push_back(measure_split_for(stream, phase_seconds, min_samples, [kernels, stream] {
            for (size_t i = 0; i < kernels; ++i) empty_kernel<<<1, 1, 0, stream>>>();
        }));
    }

    uint64_t* device_word = nullptr;
    const uint64_t expected_word = 0x7062372d72747431ULL;
    uint64_t host_word = expected_word;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_word), sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(
        device_word, &expected_word, sizeof(uint64_t), cudaMemcpyHostToDevice));
    std::cerr << "measuring blocking 8-byte D2H\n";
    const Samples d2h = measure_for(phase_seconds, min_samples, [&] {
        CUDA_CHECK(cudaMemcpyAsync(
            &host_word, device_word, sizeof(uint64_t), cudaMemcpyDeviceToHost, stream));
        CUDA_CHECK(cudaStreamSynchronize(stream));
    });
    const bool d2h_correct = host_word == expected_word;

    std::cerr << "measuring 8-byte cudaMalloc + cudaFree\n";
    const AllocationSamples allocations =
        measure_allocations_for(phase_seconds, min_samples);

    std::vector<GraphCase> graphs;
    std::vector<SplitSamples> replay;
    graphs.reserve(burst_sizes.size());
    replay.reserve(burst_sizes.size());
    for (size_t kernels : burst_sizes) {
        std::cerr << "building graph N=" << kernels << "\n";
        graphs.push_back(make_linear_graph(kernels));
        GraphCase& graph = graphs.back();
        for (size_t i = 0; i < warmups; ++i) {
            CUDA_CHECK(cudaGraphLaunch(graph.executable, stream));
            CUDA_CHECK(cudaStreamSynchronize(stream));
        }
        std::cerr << "measuring graph replay N=" << kernels << "\n";
        replay.push_back(measure_split_for(stream, phase_seconds, min_samples, [&] {
            CUDA_CHECK(cudaGraphLaunch(graph.executable, stream));
        }));
    }
    const double measurement_wall_s =
        std::chrono::duration<double>(Clock::now() - measurement_begin).count();

    CUDA_CHECK(cudaFree(device_word));
    for (GraphCase& graph : graphs) {
        CUDA_CHECK(cudaGraphExecDestroy(graph.executable));
        CUDA_CHECK(cudaGraphDestroy(graph.graph));
    }
    CUDA_CHECK(cudaStreamDestroy(stream));

    const bool timing_sane = !launch_sync.values_us.empty() && !d2h.values_us.empty() &&
        std::all_of(direct.begin(), direct.end(), [](const SplitSamples& value) {
            return !value.total.values_us.empty();
        }) &&
        std::all_of(replay.begin(), replay.end(), [](const SplitSamples& value) {
            return !value.total.values_us.empty();
        });

    std::cout << std::setprecision(12) << "{\n"
              << "\"correctness\":" << (d2h_correct ? "true" : "false") << ",\n"
              << "\"timing_sane\":" << (timing_sane ? "true" : "false") << ",\n"
              << "\"device\":{\"name\":\"" << json_escape(prop.name) << "\",\"cc\":\""
              << prop.major << '.' << prop.minor << "\",\"sm_count\":"
              << prop.multiProcessorCount << ",\"global_memory_bytes\":" << prop.totalGlobalMem
              << ",\"cuda_runtime_version\":" << runtime_version
              << ",\"cuda_driver_version\":" << driver_version << "},\n"
              << "\"parameters\":{\"target_seconds\":" << target_seconds
              << ",\"phase_seconds\":" << phase_seconds << ",\"warmups\":" << warmups
              << ",\"min_samples\":" << min_samples << ",\"burst_sizes\":[1,8,64,512,4096]},\n"
              << "\"measurement_wall_s\":" << measurement_wall_s << ",\n"
              << "\"empty_launch_sync\":" << stats_json(launch_sync) << ",\n"
              << "\"blocking_d2h_8b\":" << stats_json(d2h) << ",\n"
              << "\"allocation_8b\":{\"malloc\":" << stats_json(allocations.allocate)
              << ",\"free\":" << stats_json(allocations.release)
              << ",\"total\":" << stats_json(allocations.total) << "},\n"
              << "\"direct_bursts\":[\n";
    for (size_t i = 0; i < burst_sizes.size(); ++i) {
        if (i != 0) std::cout << ",\n";
        std::cout << "{\"kernels\":" << burst_sizes[i] << ',';
        print_split(direct[i], burst_sizes[i]);
        std::cout << '}';
    }
    std::cout << "\n],\n\"cuda_graphs\":[\n";
    for (size_t i = 0; i < burst_sizes.size(); ++i) {
        if (i != 0) std::cout << ",\n";
        std::cout << "{\"kernels\":" << burst_sizes[i]
                  << ",\"build_us\":" << graphs[i].build_us
                  << ",\"instantiate_us\":" << graphs[i].instantiate_us << ',';
        print_split(replay[i], 1);  // one graph launch, irrespective of node count.
        std::cout << '}';
    }
    std::cout << "\n]\n}\n";
    return (d2h_correct && timing_sane) ? 0 : 1;
}
