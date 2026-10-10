// Compile-time diagnostic only. The default runtime does not include this
// header or retain Trace. This header makes no CUDA call and records no
// pointer, capability, coin or value. This is owner lifecycle telemetry,
// not Rust-phase/kernel tracing.
#pragma once

#ifndef C71_OWNER_TRACE
#error "c71_owner_trace.h requires the explicit C71_OWNER_TRACE build"
#endif

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace c71_owner_trace {

struct Trace {
    // Account sizeof(Trace) in the diagnostic owner's existing host charge.
    // No heap or stdio buffer. Record storage is 512 B; conservatively allow
    // another 1 KiB stack for emit and 8 KiB for open (4 KiB parent path plus
    // scalars/system-call frames). These are additional diagnostic upper terms.
    // This ceiling is for components/short windows. A selected first group
    // skips inference/setup events and arms at the validated public A group;
    // it never extends the cap or provides a whole-replay/physical-peak credit.
    static constexpr uint64_t max_records = 131072;
    static constexpr uint64_t max_bytes = 16ULL << 20;
    static constexpr size_t record_bytes = 512;
    static constexpr size_t max_path_bytes = 4096;

    int fd = -1;
    int first_group = -1;
    uint64_t seq = 0, used = 0;
    bool failed = false, armed = true;
    int current_group = -1;

    bool open() noexcept {
        if (failed || fd >= 0 || seq || used) return reject();
        const char* selected = std::getenv("C71_OWNER_TRACE_A_FIRST");
        if (selected) {
            // Canonical decimal 0..511 only: no signs, spaces or leading zeros.
            if (!selected[0] || (selected[0] == '0' && selected[1])) return reject();
            unsigned group = 0;
            size_t digits = 0;
            for (; digits < 3 && selected[digits]; ++digits) {
                if (selected[digits] < '0' || selected[digits] > '9') return reject();
                group = 10 * group + unsigned(selected[digits] - '0');
            }
            if (selected[digits] || group > 511) return reject();
            first_group = int(group);
            armed = false;
        }
        const char* path = std::getenv("C71_OWNER_TRACE_PATH");
        if (!path || path[0] != '/') return reject();
        size_t length = 0, slash = 0;
        for (; length < max_path_bytes && path[length]; ++length)
            if (path[length] == '/') slash = length;
        if (!length || length == max_path_bytes || slash + 1 == length) return reject();
        fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return reject();
        struct stat info {};
        if (::fstat(fd, &info) || !S_ISREG(info.st_mode) || ::fchmod(fd, 0600) || !sync(fd)) {
            reject();
            close();
            return false;
        }
        char parent[max_path_bytes];
        const size_t parent_length = slash ? slash : 1;
        std::memcpy(parent, path, parent_length);
        parent[parent_length] = '\0';
        const int directory = ::open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory < 0) {
            reject();
            close();
            return false;
        }
        const bool durable = sync(directory);
        // close(EINTR) has uncertain descriptor ownership. Never retry close.
        const bool closed = ::close(directory) == 0;
        if (!durable || !closed) {
            reject();
            close();
            return false;
        }
        return true;
    }

    // Called only after the source shape's public group has been validated.
    // Returns true once, when a requested window newly arms. Existing/absent
    // selectors and other groups return false without a diagnostic failure.
    bool arm(unsigned group) noexcept {
        if (failed || fd < 0 || group > 511) return reject();
        current_group = int(group);
        if (armed || first_group < 0 || group != unsigned(first_group)) return false;
        armed = true;
        return true;
    }

    bool emit(const char* op, const char* edge, int slot, uint32_t kind,
              uint64_t logical, uint64_t capacity, uint64_t arena,
              uint64_t weights, int status, unsigned line) noexcept {
        if (failed || fd < 0) return reject();
        if (!armed) return true;
        if (seq >= max_records || slot < -1 || slot >= 512) return reject();
        const size_t operation_length = public_name_length(op);
        if (!operation_length || !edge ||
            (std::strcmp(edge, "before") && std::strcmp(edge, "after"))) return reject();
        struct timespec now {};
        if (::clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
            now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) return reject();
        const uint64_t seconds = static_cast<uint64_t>(now.tv_sec);
        const uint64_t nanos = static_cast<uint64_t>(now.tv_nsec);
        if (seconds > (std::numeric_limits<uint64_t>::max() - nanos) / 1000000000ULL)
            return reject();
        Record record;
        record.text("{\"schema\":\"volta-c71-owner-trace-v1\",\"credit\":false,\"seq\":");
        record.number(seq);
        record.text(",\"a_first\":"); record.signed_number(first_group);
        record.text(",\"a_group\":"); record.signed_number(current_group);
        record.text(",\"monotonic_ns\":"); record.number(seconds * 1000000000ULL + nanos);
        record.text(",\"op\":\""); record.text(op); record.text("\",\"edge\":\"");
        record.text(edge); record.text("\",\"slot\":"); record.signed_number(slot);
        record.text(",\"kind\":"); record.number(kind);
        record.text(",\"logical_bytes\":"); record.number(logical);
        record.text(",\"capacity_bytes\":"); record.number(capacity);
        record.text(",\"arena_bytes\":"); record.number(arena);
        record.text(",\"weights_bytes\":"); record.number(weights);
        record.text(",\"status\":"); record.signed_number(status);
        record.text(",\"line\":"); record.number(line); record.text("}\n");
        if (!record.valid || used > max_bytes || record.length > max_bytes - used)
            return reject();
        size_t sent = 0;
        while (sent < record.length) {
            const ssize_t written = ::write(fd, record.bytes + sent, record.length - sent);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return reject();
            sent += static_cast<size_t>(written);
            used += static_cast<uint64_t>(written);
        }
        ++seq;
        return true;
    }

    bool close() noexcept {
        if (first_group >= 0 && !armed) reject();
        if (fd >= 0) {
            const int closing = fd;
            fd = -1;
            // Even a failed trace must attempt its own cleanup. Runtime callers
            // must likewise complete native bookkeeping/free before propagating
            // a failed post-event and never skip native cleanup on trace failure.
            const bool durable = sync(closing);
            const bool closed = ::close(closing) == 0;
            if (!durable || !closed) reject();
        }
        return !failed;
    }

private:
    bool reject() noexcept { failed = true; return false; }

    static bool sync(int descriptor) noexcept {
        int status;
        do { status = ::fsync(descriptor); } while (status < 0 && errno == EINTR);
        return status == 0;
    }

    static size_t public_name_length(const char* op) noexcept {
        if (!op) return 0;
        for (size_t i = 0; i <= 64; ++i) {
            const char c = op[i];
            if (!c) return i;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
                  (i && c >= '0' && c <= '9'))) return 0;
        }
        return 0;
    }

    struct Record {
        char bytes[record_bytes];
        size_t length = 0;
        bool valid = true;
        void text(const char* text) noexcept {
            while (*text) {
                if (length == record_bytes) { valid = false; return; }
                bytes[length++] = *text++;
            }
        }
        void number(uint64_t value) noexcept {
            char digits[20];
            size_t count = 0;
            do { digits[count++] = char('0' + value % 10); value /= 10; } while (value);
            if (count > record_bytes - length) { valid = false; return; }
            while (count) bytes[length++] = digits[--count];
        }
        void signed_number(int value) noexcept {
            if (value < 0) { text("-"); number(uint64_t(-int64_t(value))); }
            else number(static_cast<uint64_t>(value));
        }
    };
};

static_assert(sizeof(Trace) == 32, "diagnostic owner trace charge differs");

} // namespace c71_owner_trace
