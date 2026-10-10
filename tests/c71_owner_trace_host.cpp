// File/clock/failure checks only. No CUDA, model, provider or performance credit.
#include "c71_owner_trace.h"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>

using c71_owner_trace::Trace;

static std::string read(const std::string& path) {
    std::ifstream input(path);
    assert(input.good());
    return std::string(std::istreambuf_iterator<char>(input), {});
}

int main(int argc, char** argv) {
    assert(argc == 2 && argv[1][0] == '/');
    const std::string directory = argv[1];
    const auto path = [&](const char* name) {
        const std::string result = directory + '/' + name;
        assert(::setenv("C71_OWNER_TRACE_PATH", result.c_str(), 1) == 0);
        return result;
    };
    unsigned cases = 0;
    assert(::unsetenv("C71_OWNER_TRACE_A_FIRST") == 0);
    assert(::unsetenv("C71_OWNER_TRACE_PATH") == 0);
    { Trace trace; assert(!trace.open() && trace.failed && !trace.close()); ++cases; }
    assert(::setenv("C71_OWNER_TRACE_PATH", "relative", 1) == 0);
    { Trace trace; assert(!trace.open() && trace.failed && !trace.close()); ++cases; }

    const auto ordinary = path("ordinary.jsonl");
    Trace trace;
    assert(trace.open());
    struct stat info {};
    assert(::fstat(trace.fd, &info) == 0 && (info.st_mode & 0777) == 0600);
    // The same file cannot serve two owners, even before the first closes.
    { Trace second; assert(!second.open() && second.failed && !second.close()); ++cases; }
    assert(trace.emit("allocate", "before", 3, 1, 16, 256, 0, 1024, 0, 12));
    assert(trace.emit("allocate", "after", 3, 1, 16, 256, 256, 1024, 0, 12));
    assert(trace.emit("retire_private", "before", 3, 1, 16, 256, 256, 1024, 0, 34));
    assert(trace.emit("retire_private", "after", 3, 1, 16, 256, 0, 1024, 0, 34));
    const std::string longest_name(64, 'a');
    const auto maximum = std::numeric_limits<uint64_t>::max();
    assert(trace.emit(longest_name.c_str(), "after", -1, UINT32_MAX,
                      maximum, maximum, maximum, maximum, std::numeric_limits<int>::min(), UINT32_MAX));
    assert(trace.seq == 5 && trace.close());
    const auto original = read(ordinary);
    assert(original.size() == trace.used && original.back() == '\n');
    assert(original.find("\"seq\":0") != std::string::npos);
    assert(original.find("\"seq\":4") != std::string::npos);
    assert(original.find("\"a_first\":-1,\"a_group\":-1") != std::string::npos);
    assert(original.find("\"monotonic_ns\":") != std::string::npos);
    assert(original.find("\"arena_bytes\":256") != std::string::npos);
    assert(original.find("\"status\":-2147483648") != std::string::npos);
    assert(original.find("handle") == std::string::npos && original.find("pointer") == std::string::npos);
    ++cases;
    { Trace second; assert(!second.open() && !second.close()); assert(read(ordinary) == original); ++cases; }

    const auto link = path("symlink.jsonl");
    assert(::symlink(ordinary.c_str(), link.c_str()) == 0);
    { Trace linked; assert(!linked.open() && !linked.close()); assert(read(ordinary) == original); ++cases; }
    path("bad-operation.jsonl");
    { Trace bad; assert(bad.open()); assert(!bad.emit("not public", "before", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(bad.seq == 0 && bad.used == 0 && bad.failed && !bad.close()); ++cases; }
    path("bad-slot.jsonl");
    { Trace bad; assert(bad.open()); assert(!bad.emit("allocate", "before", 512, 1, 0, 0, 0, 0, 0, 0));
      assert(bad.seq == 0 && bad.used == 0 && !bad.close()); ++cases; }
    path("bad-edge.jsonl");
    { Trace bad; assert(bad.open()); assert(!bad.emit("allocate", "pending", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(bad.seq == 0 && bad.used == 0 && !bad.close()); ++cases; }
    path("record-ceiling.jsonl");
    { Trace full; assert(full.open()); full.seq = Trace::max_records;
      assert(!full.emit("allocate", "before", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(full.used == 0 && full.failed && !full.close()); ++cases; }
    path("byte-ceiling.jsonl");
    { Trace full; assert(full.open()); full.used = Trace::max_bytes;
      assert(!full.emit("allocate", "before", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(full.seq == 0 && full.failed && !full.close()); ++cases; }
    path("write-failure.jsonl");
    { Trace broken; assert(broken.open()); assert(::close(broken.fd) == 0);
      assert(!broken.emit("allocate", "before", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(broken.failed && broken.seq == 0 && broken.used == 0);
      assert(!broken.emit("allocate", "after", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(!broken.close() && broken.fd == -1); ++cases; }
    path("closed.jsonl");
    { Trace closed; assert(closed.open() && closed.close());
      assert(!closed.emit("allocate", "before", 0, 1, 0, 0, 0, 0, 0, 0));
      assert(closed.failed && !closed.close()); ++cases; }
    // Invalid selectors fail before creating any trace file.
    const auto invalid_path = path("invalid-selector.jsonl");
    for (const char* selected : {"", "-1", "+1", " 34", "34 ", "03", "512", "1000", "1x"}) {
        assert(::setenv("C71_OWNER_TRACE_A_FIRST", selected, 1) == 0);
        Trace invalid;
        assert(!invalid.open() && invalid.failed && invalid.fd == -1 && !invalid.close());
        assert(::access(invalid_path.c_str(), F_OK) == -1);
        ++cases;
    }
    const auto selected_path = path("selected-window.jsonl");
    assert(::setenv("C71_OWNER_TRACE_A_FIRST", "34", 1) == 0);
    {
        Trace selected;
        assert(selected.open() && selected.first_group == 34 && !selected.armed);
        assert(selected.emit("allocate", "before", 0, 1, 16, 256, 256, 1024, 0, 12));
        assert(selected.seq == 0 && selected.used == 0 && read(selected_path).empty());
        assert(!selected.arm(33) && selected.current_group == 33 && !selected.failed);
        assert(selected.emit("fence", "before", -1, 0, 0, 0, 256, 1024, 0, 12));
        assert(selected.seq == 0 && selected.used == 0);
        assert(selected.arm(34) && selected.armed && selected.current_group == 34);
        assert(selected.emit("snapshot", "after", 0, 1, 16, 256, 256, 1024, 0, 12));
        assert(!selected.arm(34) && !selected.failed);
        assert(!selected.arm(35) && selected.current_group == 35 && !selected.failed);
        assert(selected.emit("allocate", "before", 1, 1, 16, 256, 256, 1024, 0, 12));
        assert(selected.seq == 2 && selected.close());
        const auto records = read(selected_path);
        assert(records.find("\"a_first\":34,\"a_group\":34") != std::string::npos);
        assert(records.find("\"a_first\":34,\"a_group\":35") != std::string::npos);
        ++cases;
    }
    path("unreached-window.jsonl");
    { Trace unreached; assert(unreached.open() && !unreached.armed);
      assert(!unreached.arm(33) && !unreached.failed);
      assert(!unreached.close() && unreached.failed && unreached.fd == -1); ++cases; }
    for (const char* selected : {"0", "511"}) {
        path(selected[0] == '0' ? "first-zero.jsonl" : "first-last.jsonl");
        assert(::setenv("C71_OWNER_TRACE_A_FIRST", selected, 1) == 0);
        Trace endpoint;
        assert(endpoint.open() && !endpoint.armed);
        assert(endpoint.arm(unsigned(endpoint.first_group)) && endpoint.armed && endpoint.close());
        ++cases;
    }
    assert(::unsetenv("C71_OWNER_TRACE_A_FIRST") == 0);
    assert(cases == 26);
    std::printf("C71_OWNER_TRACE_HOST {\"cases\":%u,\"state_bytes\":%zu,"
                "\"record_storage_bytes\":%zu,\"maximum_records\":%llu,\"maximum_file_bytes\":%llu,"
                "\"gpu_execution\":false,\"credit\":false}\n", cases, sizeof(Trace), Trace::record_bytes,
                static_cast<unsigned long long>(Trace::max_records),
                static_cast<unsigned long long>(Trace::max_bytes));
}
