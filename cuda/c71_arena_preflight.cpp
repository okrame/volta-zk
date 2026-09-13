// Native, host-only validation of offsets in one device-arena plan.
// No cudaMalloc, device execution or claim about unknown backend workspaces.
#include <array>
#include <cstdint>
#include <iostream>
struct Span { std::uint64_t start=0, size=0; bool live=false; };
int main() {
    constexpr std::uint64_t arena=6442450944ULL, margin=256ULL<<20;
    std::array<Span,512> spans{};
    std::uint64_t high=0, live=0;
    char op; unsigned id; std::uint64_t a,b;
    while (std::cin >> op) {
        if (!(std::cin >> id >> a >> b)) return 7;
        if (id>=spans.size()) return 2;
        auto &s=spans[id];
        if (op=='F') {
            if (!s.live || a!=1 || b!=0) return 3; // completed fence required
            live-=s.size; s.live=false;
        } else if (op=='A') {
            if (s.live || a%256 || b%256 || a>arena-margin || b>arena-margin-a) return 4;
            for (const auto &other:spans)
                if (other.live && b && other.size && a<other.start+other.size && other.start<a+b) return 5;
            s={a,b,true}; live+=b; if (a+b>high) high=a+b;
        } else return 6;
    }
    if (!std::cin.eof()) return 7;
    std::cout << high << ' ' << live << ' ' << sizeof(spans) << '\n';
}
