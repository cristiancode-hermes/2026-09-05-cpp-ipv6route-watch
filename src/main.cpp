// SPDX-License-Identifier: MIT
// cpp-ipv6route-watch — IPv6 routing table inspector (/proc/net/ipv6_route + rt6_stats)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ipv6route-watch
// Usage: ./ipv6route-watch [options]

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static void enable_color() {
  C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
  C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
  C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────
struct Route {
  std::array<uint16_t, 8> dest{};
  int plen = 0;
  std::string dest_str;
  std::array<uint16_t, 8> src{};
  int src_plen = 0;
  std::string src_str;
  std::array<uint16_t, 8> gw{};
  std::string gw_str;
  long metric = 0;
  long refcnt = 0;
  long use = 0;
  unsigned flags = 0;
  std::string iface;
  std::string type;              // local/anycast/multicast/link/default/unicast/reject/nat/unreachable/blackhole/throw
};

struct SnapStats {
  int routes = 0;
  int local = 0;
  int anycast = 0;
  int multicast = 0;
  int link = 0;
  int default_ = 0;
  int reject = 0;
  int nat = 0;
  int unreachable = 0;
  int blackhole = 0;
  int throw_ = 0;
  int unicast = 0;
  int unique_ifaces = 0;
  std::vector<std::string> ifaces;
  int plen_count[129] = {};
  int max_plen = 0;
  bool demo = false;
};

struct Inet6Iface {
  std::string addr;
  std::string iface;
  int plen = 0;
  unsigned flags = 0;
};

struct Snapshot {
  long ts = 0;
  std::vector<Route> routes;
  std::vector<Inet6Iface> addrs;
  SnapStats stats;
  bool demo = false;
  std::string route_source, stat_source, addr_source;
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static long parse_long(std::string_view v) {
  v = trim(v);
  long out = 0;
  std::from_chars(v.data(), v.data() + v.size(), out);
  return out;
}

static bool parse_addr32(std::string_view hex, std::array<uint16_t, 8>& words) {
  if (hex.size() != 32) return false;
  for (int i = 0; i < 8; ++i) {
    int v = 0;
    for (int j = 0; j < 4; ++j) {
      int d = hex_val(hex[i * 4 + j]);
      if (d < 0) return false;
      v = v * 16 + d;
    }
    words[static_cast<std::size_t>(i)] = static_cast<uint16_t>(v);
  }
  return true;
}

// RFC 5952 compression (longest zero-word run >= 2; ties -> first)
static std::string compress_ipv6(const std::array<uint16_t, 8>& w) {
  int best_start = -1, best_len = 0;
  int i = 0;
  while (i < 8) {
    if (w[static_cast<std::size_t>(i)] == 0) {
      int j = i;
      while (j < 8 && w[static_cast<std::size_t>(j)] == 0) ++j;
      int len = j - i;
      if (len >= 2 && len > best_len) { best_start = i; best_len = len; }
      i = j;
    } else {
      ++i;
    }
  }
  auto fmt_word = [&](int k) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", w[static_cast<std::size_t>(k)]);
    return std::string(buf);
  };
  if (best_start < 0) {
    std::string full;
    for (int k = 0; k < 8; ++k) {
      if (!full.empty()) full += ':';
      full += fmt_word(k);
    }
    return full;
  }
  std::string left, right;
  for (int k = 0; k < best_start; ++k) {
    if (!left.empty()) left += ':';
    left += fmt_word(k);
  }
  for (int k = best_start + best_len; k < 8; ++k) {
    if (!right.empty()) right += ':';
    right += fmt_word(k);
  }
  return left + "::" + right;
}

static std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\t': out += "\\t"; break;
      default: out += c;
    }
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Flag decoding
// ─────────────────────────────────────────────────────────────────────────────
static std::string flag_names(unsigned f) {
  std::string out;
  auto add = [&](unsigned bit, const char* name) {
    if ((f & bit) != 0) {
      if (!out.empty()) out += "|";
      out += name;
    }
  };
  add(0x1, "UP"); add(0x2, "GATEWAY"); add(0x4, "HOST"); add(0x8, "REJECT");
  add(0x10, "DYNAMIC"); add(0x20, "MODIFIED"); add(0x40, "DEFAULT");
  add(0x80, "ALLONLINK"); add(0x100, "ADDRCONF"); add(0x200, "NONEXTHOP");
  add(0x400, "CACHE"); add(0x800, "FLOW"); add(0x1000, "POLICY");
  add(0x8000, "LOCAL"); add(0x10000, "MULTICAST"); add(0x20000, "ANYCAST");
  add(0x40000, "NAT");
  return out.empty() ? "-" : out;
}

// Shared empty assigned-address set (preliminary classification in the parser;
// refine_types() re-applies with the real set).
static const std::unordered_set<std::string> EMPTY_ASSIGNED;

static std::string classify_route(const Route& r, const std::unordered_set<std::string>& assigned) {
  if ((r.flags & 0x4000) != 0 || (r.flags & 0x8000) != 0) return "local";
  if ((r.flags & 0x10000) != 0) return "multicast";
  if ((r.flags & 0x20000) != 0) return "anycast";
  if ((r.flags & 0x40000) != 0) return "nat";
  if ((r.flags & 0x8) != 0) return "reject";
  if (r.dest_str == "::" && r.plen == 0) return "default";
  if (r.dest_str == "::1") return "local";
  if (assigned.contains(r.dest_str)) return "local";
  const auto& w = r.dest;
  if ((w[0] & 0xffc0) == 0xfe80) return "link";       // fe80::/10
  if ((w[0] & 0xff00) == 0xff00) return "multicast";  // ff00::/8
  return "unicast";
}

// Re-classify every route with the full snapshot context (assigned-address set).
static void refine_types(Snapshot& s) {
  std::unordered_set<std::string> assigned;
  for (const auto& a : s.addrs) assigned.insert(a.addr);
  for (auto& r : s.routes) {
    if (r.type == "unreachable" || r.type == "blackhole" || r.type == "throw" || r.type == "nat")
      continue;  // literal kernel type token
    r.type = classify_route(r, assigned);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Route line parser
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_route_line(std::string_view line, Route& r) {
  std::vector<std::string> toks;
  {
    std::istringstream ss{std::string(line)};
    std::string t;
    while (ss >> t) toks.push_back(std::move(t));
  }
  if (toks.size() < 9) return false;
  bool literal_type = false;
  // Kernel prints a literal type token for RTN_UNREACHABLE / BLACKHOLE / THROW / NAT
  if (toks[0] == "unreachable") { r.type = "unreachable"; literal_type = true; }
  else if (toks[0] == "blackhole") { r.type = "blackhole"; literal_type = true; }
  else if (toks[0] == "throw") { r.type = "throw"; literal_type = true; }
  else if (toks[0] == "nat") { r.type = "nat"; literal_type = true; }
  if (literal_type) {
    // unreachable 00 0000... 00 0000... metric refcnt use flags iface
    // token layout: [type] plen src srcplen gw metric refcnt use flags iface (10 tokens)
    std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), r.plen, 16);
    if (!parse_addr32(toks[2], r.src)) return false;
    std::from_chars(toks[3].data(), toks[3].data() + toks[3].size(), r.src_plen, 16);
    if (!parse_addr32(toks[4], r.gw)) return false;
    if (toks.size() >= 6) r.metric = parse_long(toks[5]);
    if (toks.size() >= 7) r.refcnt = parse_long(toks[6]);
    if (toks.size() >= 8) r.use    = parse_long(toks[7]);
    unsigned long fl = 0;
    std::from_chars(toks[8].data(), toks[8].data() + toks[8].size(), fl, 16);
    r.flags = static_cast<unsigned>(fl);
    r.iface = toks.size() >= 10 ? toks[9] : "";
    r.dest_str = "::";  // no dest printed for these rows
    r.src_str = compress_ipv6(r.src);
    r.gw_str = compress_ipv6(r.gw);
    if (r.gw_str == "::") r.gw_str.clear();
    return true;
  }
  if (!parse_addr32(toks[0], r.dest)) return false;
  std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), r.plen, 16);   // plen is %02x hex
  if (!parse_addr32(toks[2], r.src)) return false;
  std::from_chars(toks[3].data(), toks[3].data() + toks[3].size(), r.src_plen, 16);
  if (!parse_addr32(toks[4], r.gw)) return false;
  r.metric = parse_long(toks[5]);
  r.refcnt = parse_long(toks[6]);
  r.use    = parse_long(toks[7]);
  unsigned long fl = 0;
  std::from_chars(toks[8].data(), toks[8].data() + toks[8].size(), fl, 16);
  r.flags = static_cast<unsigned>(fl);
  r.iface = toks.size() >= 10 ? toks[9] : "";
  r.dest_str = compress_ipv6(r.dest);
  r.src_str  = compress_ipv6(r.src);
  r.gw_str   = compress_ipv6(r.gw);
  if (r.gw_str == "::") r.gw_str.clear();
  r.type = classify_route(r, EMPTY_ASSIGNED);   // preliminary; refine_types() redoes it with context
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// rt6_stats — 6 cumulative counters printed as one %08x line
//   0 fib6_walkers  1 fib6_trees  2 fib6_table_entries
//   3 fib6_rt_entries  4 fib6_rt_cache  5 fib6_discarded_routes
// ─────────────────────────────────────────────────────────────────────────────
static std::array<long long, 6> parse_rt6_stats(std::string_view line) {
  std::array<long long, 6> out{0, 0, 0, 0, 0, 0};
  std::istringstream ss{std::string(line)};
  for (auto& v : out) {
    std::string tok;
    ss >> tok;
    if (tok.empty()) break;
    long long x = 0;
    std::from_chars(tok.data(), tok.data() + tok.size(), x, 16);
    v = x;
  }
  return out;
}

static std::array<long long, 6> read_rt6_from(std::string_view path) {
  std::array<long long, 6> out{0, 0, 0, 0, 0, 0};
  if (path.empty()) return out;
  std::ifstream f{std::string(path)};
  std::string line;
  if (f && std::getline(f, line)) out = parse_rt6_stats(trim(line));
  return out;
}

static void compute_stats(Snapshot& s);   // fwd (used by load_snapshot)

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot loading
// ─────────────────────────────────────────────────────────────────────────────
static bool load_snapshot(Snapshot& s, std::string_view file, bool demo) {
  s.demo = demo;
  if (demo) {
    const char* demo_rows[] = {
      // ::/0 default via fe80::1 on eth0  (UP|GATEWAY|DEFAULT|ADDRCONF = 0x143)
      "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000143  eth0",
      // ::/0 default via fe80::2 on wg0
      "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000000 00000001 00000000 00000143  wg0",
      // ::1/128 local on lo
      "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00008005  lo",
      // fe80::/64 link route on eth0 (UP|ALLONLINK|ADDRCONF = 0x181)
      "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000101  eth0",
      // 2001:db8:1::1/128 local assigned addr on eth0 (UP|HOST|LOCAL = 0x8005)
      "20010db8000100000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00008005  eth0",
      // 2001:db8:1::/64 via fe80::1 (UP|GATEWAY|ADDRCONF = 0x103)
      "20010db8000100000000000000000000 40 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000100 00000001 00000000 00000103  eth0",
      // fd00::/8 ULA via fe80::2 on wg0
      "fd000000000000000000000000000000 08 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000100 00000001 00000000 00000103  wg0",
      // ff00::/8 multicast default on eth0 (UP|MULTICAST = 0x10001)
      "ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00010001  eth0",
      // 2001:db8:2::/64 on-link dev eth0
      "20010db8000200000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000181  eth0",
      // anycast 2001:db8:3::1/128 on lo (UP|HOST|ANYCAST = 0x20005)
      "20010db8000300000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00020005  lo",
      // literal type row: unreachable (scope 255 style)
      "unreachable 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000201  lo",
      // literal type row: blackhole
      "blackhole 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000201  lo",
    };
    for (auto row : demo_rows) {
      Route r;
      if (parse_route_line(row, r)) s.routes.push_back(std::move(r));
    }
    s.route_source = "demo";
    s.stat_source = "demo";
    s.addr_source = "demo";
    s.ts = std::time(nullptr);
    refine_types(s);
    compute_stats(s);
    return !s.routes.empty();
  }

  if (file.empty()) {
    std::ifstream f("/proc/net/ipv6_route");
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
      std::string_view lv = trim(line);
      if (lv.empty() || lv.front() == '#') continue;
      Route r;
      if (parse_route_line(lv, r)) s.routes.push_back(std::move(r));
    }
    s.route_source = "/proc/net/ipv6_route";
    std::ifstream st("/proc/net/rt6_stats");
    if (st) {
      std::string sl;
      if (std::getline(st, sl)) s.stat_source = "/proc/net/rt6_stats";
    } else {
      s.stat_source = "n/a";
    }
  } else {
    std::ifstream f{std::string(file)};
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
      std::string_view lv = trim(line);
      if (lv.empty() || lv.front() == '#') continue;
      Route r;
      if (parse_route_line(lv, r)) s.routes.push_back(std::move(r));
    }
    s.route_source = std::string(file);
    s.stat_source = "n/a";
  }

  s.addr_source = "n/a";
  std::ifstream ia("/proc/net/if_inet6");
  if (ia) {
    std::string line;
    while (std::getline(ia, line)) {
      std::string_view lv = trim(line);
      if (lv.empty()) continue;
      // addr plen scope flags [devflags] name — kernel version varies in the
      // middle columns; only addr (token 0) and iface (last token) are needed.
      std::vector<std::string> toks;
      {
        std::istringstream ss{std::string(lv)};
        std::string t;
        while (ss >> t) toks.push_back(std::move(t));
      }
      if (toks.size() < 3) continue;
      std::array<uint16_t, 8> w{};
      if (toks[0].size() == 32 && parse_addr32(toks[0], w)) {
        Inet6Iface e;
        e.addr = compress_ipv6(w);
        e.iface = toks.back();
        std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), e.plen, 16);
        if (toks.size() >= 4) {
          unsigned fl = 0;
          std::from_chars(toks[3].data(), toks[3].data() + toks[3].size(), fl, 16);
          e.flags = fl;
        }
        s.addrs.push_back(std::move(e));
      }
    }
    if (!s.addrs.empty()) s.addr_source = "/proc/net/if_inet6";
  }
  s.ts = std::time(nullptr);
  refine_types(s);
  compute_stats(s);
  return true;
}

static void compute_stats(Snapshot& s) {
  SnapStats st;
  st.routes = static_cast<int>(s.routes.size());
  for (const auto& r : s.routes) {
    if      (r.type == "local")       st.local++;
    else if (r.type == "anycast")     st.anycast++;
    else if (r.type == "multicast")   st.multicast++;
    else if (r.type == "link")        st.link++;
    else if (r.type == "default")     st.default_++;
    else if (r.type == "reject")      st.reject++;
    else if (r.type == "nat")         st.nat++;
    else if (r.type == "unreachable") st.unreachable++;
    else if (r.type == "blackhole")   st.blackhole++;
    else if (r.type == "throw")       st.throw_++;
    else                              st.unicast++;
    if (r.plen >= 0 && r.plen <= 128) st.plen_count[r.plen]++;
    st.max_plen = std::max(st.max_plen, r.plen);
    bool seen = false;
    for (const auto& i : st.ifaces) if (i == r.iface) { seen = true; break; }
    if (!seen && !r.iface.empty()) st.ifaces.push_back(r.iface);
  }
  std::sort(st.ifaces.begin(), st.ifaces.end());
  st.unique_ifaces = static_cast<int>(st.ifaces.size());
  st.demo = s.demo;
  s.stats = st;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────
static const char* type_color(const std::string& t) {
  if (t == "local" || t == "anycast" || t == "default") return C_GREEN.c_str();
  if (t == "multicast" || t == "link") return C_YELLOW.c_str();
  if (t == "reject" || t == "unreachable" || t == "blackhole" || t == "throw" || t == "nat") return C_RED.c_str();
  return C_DIM.c_str();
}

static void render_routes(const Snapshot& s, int top, bool all) {
  std::cout << C_BOLD << "-- IPv6 routing table  " << C_RESET << C_DIM << s.route_source << C_RESET << " --\n";
  std::cout << C_DIM << "  DEST                                    PLEN  SRC                                      GATEWAY                     METRIC  FLAGS                        IFACE\n" << C_RESET;
  int shown = 0;
  for (const auto& r : s.routes) {
    if (!all && r.type == "local" && r.plen == 128 && r.iface == "lo") continue;
    if (top > 0 && shown >= top) break;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "/%d", r.plen);
    // Literal kernel types (unreachable/blackhole/throw/nat) print their name
    // instead of a destination in /proc — mirror that in the table.
    bool literal = r.type == "unreachable" || r.type == "blackhole" ||
                   r.type == "throw" || r.type == "nat";
    std::string dest = literal ? r.type : r.dest_str + buf;
    std::cout << "  " << type_color(r.type) << C_BOLD
              << std::setw(40) << std::left << dest << C_RESET
              << std::setw(6) << std::left << r.plen
              << std::setw(40) << std::left << r.src_str
              << std::setw(28) << std::left << (r.gw_str.empty() ? "::" : r.gw_str)
              << std::setw(9) << std::left << r.metric
              << C_DIM << std::setw(26) << std::left << flag_names(r.flags) << C_RESET << " "
              << type_color(r.type) << r.iface << C_RESET << "\n";
    ++shown;
  }
  if (shown == 0) std::cout << "  " << C_DIM << "(no routes to show; try --all)" << C_RESET << "\n";
}

static void render_stats(const Snapshot& s) {
  const auto& st = s.stats;
  std::cout << C_BOLD << "-- IPv6 FIB summary  " << C_RESET << C_DIM << s.route_source << C_RESET << " --\n";
  std::cout << "  " << C_BOLD << "routes " << C_RESET << st.routes
            << "   " << C_BOLD << "ifaces " << C_RESET << st.unique_ifaces
            << "   " << C_BOLD << "max_plen " << C_RESET << st.max_plen
            << "   " << C_BOLD << "source " << C_RESET << C_DIM << s.route_source << C_RESET << "\n  ";
  std::cout << C_GREEN << "local " << C_RESET << st.local
            << "  " << C_GREEN << "anycast " << C_RESET << st.anycast
            << "  " << C_YELLOW << "multicast " << C_RESET << st.multicast
            << "  " << C_YELLOW << "link(fe80) " << C_RESET << st.link
            << "  " << C_YELLOW << "default(::/0) " << C_RESET << st.default_ << "\n  ";
  std::cout << C_RED << "reject " << C_RESET << st.reject
            << "  " << C_RED << "unreachable " << C_RESET << st.unreachable
            << "  " << C_RED << "blackhole " << C_RESET << st.blackhole
            << "  " << C_RED << "throw " << C_RESET << st.throw_
            << "  " << C_MAGENTA << "nat " << C_RESET << st.nat
            << "  " << C_BOLD << "unicast " << C_RESET << st.unicast << "\n";
  std::cout << C_DIM << "  plen histogram: " << C_RESET;
  int emitted = 0;
  for (int p = 0; p <= 128 && emitted < 10; ++p) {
    if (st.plen_count[p] > 0) {
      std::cout << p << ":" << st.plen_count[p] << " ";
      ++emitted;
    }
  }
  std::cout << "\n";
  if (!s.addrs.empty())
    std::cout << C_DIM << "  assigned addrs (if_inet6): " << C_RESET << s.addrs.size()
              << "  from " << C_DIM << s.addr_source << C_RESET << "\n";
}

static void render_ifaces(const Snapshot& s) {
  std::cout << C_BOLD << "-- interfaces with IPv6 routes --\n" << C_RESET;
  std::vector<std::pair<std::string, int>> counts;
  for (const auto& i : s.stats.ifaces) {
    int n = 0;
    for (const auto& r : s.routes) if (r.iface == i) ++n;
    counts.emplace_back(i, n);
  }
  for (const auto& [name, n] : counts)
    std::cout << "  " << C_CYAN << std::setw(12) << std::left << name << C_RESET << n << " route(s)\n";
}

static void render_rt6(const std::array<long long, 6>& a, const std::array<long long, 6>& b,
                       std::string_view source, bool delta) {
  const char* names[6] = {"fib6_walkers", "fib6_trees", "fib6_table_entries",
                          "fib6_rt_entries", "fib6_rt_cache", "fib6_discarded_routes"};
  std::cout << C_BOLD << "-- rt6_stats cumulative counters  " << C_RESET << C_DIM << source << C_RESET << " --\n";
  for (int i = 0; i < 6; ++i) {
    const char* c = C_GREEN.c_str();
    if (delta && b[i] > a[i]) c = C_YELLOW.c_str();
    std::cout << "  " << std::setw(22) << std::left << names[i]
              << C_DIM << "cur " << C_RESET << std::setw(12) << a[i]
              << C_DIM << "nxt " << C_RESET << c << std::setw(12) << b[i] << C_RESET;
    if (delta) std::cout << C_MAGENTA << "delta " << C_RESET << (b[i] - a[i]);
    std::cout << "\n";
  }
}

static void render_json(const Snapshot& s) {
  std::cout << "{\n";
  std::cout << "  \"ts\": " << s.ts << ",\n";
  std::cout << "  \"source\": \"" << json_escape(s.route_source) << "\",\n";
  std::cout << "  \"demo\": " << (s.demo ? "true" : "false") << ",\n";
  std::cout << "  \"summary\": {\n";
  std::cout << "    \"routes\": " << s.stats.routes << ",\n";
  std::cout << "    \"ifaces\": " << s.stats.unique_ifaces << ",\n";
  std::cout << "    \"types\": {\"local\": " << s.stats.local
            << ", \"anycast\": " << s.stats.anycast
            << ", \"multicast\": " << s.stats.multicast
            << ", \"link\": " << s.stats.link
            << ", \"default\": " << s.stats.default_
            << ", \"reject\": " << s.stats.reject
            << ", \"unreachable\": " << s.stats.unreachable
            << ", \"blackhole\": " << s.stats.blackhole
            << ", \"throw\": " << s.stats.throw_
            << ", \"nat\": " << s.stats.nat
            << ", \"unicast\": " << s.stats.unicast << "}\n";
  std::cout << "  },\n";
  std::cout << "  \"routes\": [\n";
  for (std::size_t i = 0; i < s.routes.size(); ++i) {
    const auto& r = s.routes[i];
    std::cout << "    {\"dest\": \"" << json_escape(r.dest_str) << "\", \"plen\": " << r.plen
              << ", \"src\": \"" << json_escape(r.src_str) << "\""
              << ", \"gateway\": \"" << json_escape(r.gw_str) << "\""
              << ", \"metric\": " << r.metric
              << ", \"refcnt\": " << r.refcnt
              << ", \"flags\": \"" << flag_names(r.flags) << "\""
              << ", \"type\": \"" << r.type << "\""
              << ", \"iface\": \"" << json_escape(r.iface) << "\"}";
    if (i + 1 < s.routes.size()) std::cout << ",";
    std::cout << "\n";
  }
  std::cout << "  ]\n";
  std::cout << "}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void t_check(bool ok, const char* name) {
  if (ok) { ++g_pass; std::cout << "  PASS  " << name << "\n"; }
  else    { ++g_fail; std::cout << "  FAIL  " << name << "\n"; }
}

static int run_selftest() {
  std::cout << "-- selftest: IPv6 compression / parsing --\n";
  {
    std::array<uint16_t, 8> w{};
    t_check(parse_addr32("00000000000000000000000000000001", w) && compress_ipv6(w) == "::1", "::1 compressed");
    t_check(parse_addr32("00000000000000000000000000000000", w) && compress_ipv6(w) == "::", "unspecified ::");
    t_check(parse_addr32("fe800000000000000000000000000000", w) && compress_ipv6(w) == "fe80::", "fe80:: compressed");
    t_check(parse_addr32("20010db8000000000000000000000001", w) && compress_ipv6(w) == "2001:db8::1", "2001:db8::1");
    t_check(parse_addr32("20010db8123400000000000000000001", w) && compress_ipv6(w) == "2001:db8:1234::1", "embed ::1");
    t_check(parse_addr32("20010db8000000000001000000000001", w) && compress_ipv6(w) == "2001:db8::1:0:0:1", "tie -> first run");
    t_check(parse_addr32("20010db8000000000000000000000002", w) && compress_ipv6(w) == "2001:db8::2", "trailing run");
    t_check(parse_addr32("123456789abcdef0123456789abcdef0", w) && compress_ipv6(w) == "1234:5678:9abc:def0:1234:5678:9abc:def0", "full 8 groups");
    t_check(!parse_addr32("1234", w), "short hex rejected");
    t_check(!parse_addr32("gg0000000000000000000000000000001", w), "non-hex rejected");
  }
  std::cout << "-- selftest: route line parser --\n";
  {
    Route r;
    // real 10-token row (shape of /proc/net/ipv6_route on this host)
    bool ok = parse_route_line(
      "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000006 00000000 80200001       lo", r);
    t_check(ok, "real-shaped row parses");
    if (ok) {
      t_check(r.dest_str == "::1", "dest ::1");
      t_check(r.plen == 128, "plen 128");
      t_check(r.iface == "lo", "iface lo");
      t_check(r.type == "local", "classified local (LOCAL flag)");
      t_check(r.flags == 0x80200001u, "flags parsed hex");
    }
    Route u;
    bool uk = parse_route_line(
      "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000143  eth0", u);
    t_check(uk && u.type == "default", "::/0 default classified");
    t_check(uk && u.gw_str == "fe80::1", "gateway decoded fe80::1");
    t_check(uk && !u.gw_str.empty(), "gateway present");
    Route lit;
    bool lk = parse_route_line(
      "unreachable 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000201  lo", lit);
    t_check(lk && lit.type == "unreachable", "literal unreachable type");
    Route bh;
    bool bk = parse_route_line(
      "blackhole 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000201  lo", bh);
    t_check(bk && bh.type == "blackhole", "literal blackhole type");
  }
  std::cout << "-- selftest: flags / helpers --\n";
  {
    std::string fn = flag_names(0x143);
    t_check(fn.find("DEFAULT") != std::string::npos, "0x143 has DEFAULT");
    t_check(fn.find("ADDRCONF") != std::string::npos, "0x143 has ADDRCONF");
    t_check(flag_names(0) == "-", "no flags -> -");
    std::array<long long, 6> a = parse_rt6_stats("0001 0002 0004 0001 0000 0000");
    t_check(a[0] == 1 && a[2] == 4 && a[3] == 1, "rt6 stats hex parse");
    t_check(parse_long("  42") == 42, "parse_long trims");
    t_check(trim("  abc \t") == "abc", "trim");
  }
  std::cout << "-- selftest: demo snapshot --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, "", true);
    t_check(ok, "demo loads");
    if (ok) {
      const auto& st = s.stats;
      t_check(st.routes == 12, "demo has 12 routes");
      t_check(st.local == 2, "demo local count 2");
      t_check(st.anycast == 1, "demo anycast count 1");
      t_check(st.multicast == 1, "demo multicast count 1");
      t_check(st.link == 1, "demo link count 1");
      t_check(st.default_ == 2, "demo ::/0 count 2");
      t_check(st.unreachable == 1, "demo unreachable count 1");
      t_check(st.blackhole == 1, "demo blackhole count 1");
      t_check(st.unique_ifaces == 3, "demo ifaces lo/eth0/wg0");
      t_check(st.plen_count[128] == 3, "demo plen 128 count 3");
      t_check(st.plen_count[0] == 4, "demo plen 0 count 4 (2 defaults + 2 literal rows)");
    }
  }
  std::cout << "-- selftest: real /proc/net source --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, "", false);
    t_check(ok, "/proc/net/ipv6_route opens");
    if (ok) {
      t_check(!s.routes.empty(), "host has routes");
      t_check(s.stats.routes == static_cast<int>(s.routes.size()), "stats.routes consistent");
      t_check(s.stats.unique_ifaces >= 1, "at least 1 iface");
      bool has_lo = false;
      for (const auto& r : s.routes) if (r.iface == "lo") has_lo = true;
      t_check(has_lo, "lo iface present");
    }
  }
  std::cout << "-- selftest: JSON hygiene --\n";
  {
    Snapshot s;
    load_snapshot(s, "", true);
    std::ostringstream os;
    std::streambuf* old = std::cout.rdbuf(os.rdbuf());
    render_json(s);
    std::cout.rdbuf(old);
    std::string j = os.str();
    t_check(j.find("\"routes\"") != std::string::npos, "json has routes array");
    t_check(j.find("\"summary\"") != std::string::npos, "json has summary");
    t_check(j.find("\"dest\": \"::1\", \"plen\": 128") != std::string::npos, "json route fields quoted");
    t_check(j.find("{dest:") == std::string::npos, "json keys always quoted");
    t_check(j.find("\"type\": \"unreachable\"") != std::string::npos, "json literal type");
  }
  std::cout << "-- selftest: --no-color hygiene --\n";
  {
    Snapshot s;
    load_snapshot(s, "", true);
    disable_color();
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_stats(s);
    render_routes(s, 0, false);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    t_check(out.find("IPv6") != std::string::npos, "output has content");
    enable_color();
  }
  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "ipv6route-watch — IPv6 routing table inspector (/proc/net/ipv6_route + rt6_stats)\n"
    "\n"
    "Usage: ipv6route-watch [options]\n"
    "\n"
    "  (default)    FIB summary + route table\n"
    "  --stats      summary only\n"
    "  --routes     route table only\n"
    "  --all        include pure host-local lo routes\n"
    "  --top N      show first N routes\n"
    "  --ifaces     per-interface route counts\n"
    "  --rt6        rt6_stats cumulative counters (2 reads -> delta)\n"
    "  --json       machine-readable output\n"
    "  --demo       synthetic router host (12 routes)\n"
    "  --file PATH  parse a dump (tolerates # comments)\n"
    "  --watch N    refresh every N seconds\n"
    "  --no-color   disable ANSI colors\n"
    "  --selftest   run self-tests and exit\n"
    "  -h, --help   this help\n";
}

enum class Mode { Auto, Stats, Routes, Ifaces, Rt6 };

int main(int argc, char** argv) {
  bool color_flag = true, demo = false, json = false, all = false;
  int watch = 0, top = 0;
  std::string file;
  Mode mode = Mode::Auto;

  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) { std::cerr << "error: " << name << " requires a value\n"; return std::nullopt; }
      return std::string(argv[++i]);
    };
    if (a == "--stats")        mode = Mode::Stats;
    else if (a == "--routes")  mode = Mode::Routes;
    else if (a == "--ifaces")  mode = Mode::Ifaces;
    else if (a == "--rt6")     mode = Mode::Rt6;
    else if (a == "--file")    { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")     { auto v = next(a); if (!v) return 2; top = std::atoi(v->c_str()); }
    else if (a == "--watch")   { auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--demo")    demo = true;
    else if (a == "--json")    json = true;
    else if (a == "--all")     all = true;
    else if (a == "--no-color") color_flag = false;
    else if (a == "--selftest") return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  auto run_once = [&](const Snapshot& snap) {
    if (json) { render_json(snap); return; }
    switch (mode) {
      case Mode::Auto:
        render_stats(snap);
        std::cout << "\n";
        render_routes(snap, top > 0 ? top : 12, all);
        break;
      case Mode::Stats:  render_stats(snap); break;
      case Mode::Routes: render_routes(snap, top, true); break;
      case Mode::Ifaces: render_ifaces(snap); break;
      case Mode::Rt6: {
        std::string src = snap.stat_source == "n/a" || snap.stat_source.empty() ? "/proc/net/rt6_stats" : snap.stat_source;
        if (src == "/proc/net/rt6_stats") {
          auto a = read_rt6_from(src);
          std::this_thread::sleep_for(std::chrono::milliseconds(300));
          auto b = read_rt6_from(src);
          render_rt6(a, b, src, true);
        } else {
          auto a = read_rt6_from("/proc/net/rt6_stats");
          auto b = read_rt6_from("/proc/net/rt6_stats");
          render_rt6(a, b, "/proc/net/rt6_stats", true);
        }
        break;
      }
    }
  };

  if (watch > 0) {
    for (;;) {
      Snapshot snap;
      if (!load_snapshot(snap, file, demo)) { std::cerr << "error: cannot read IPv6 route sources\n"; return 1; }
      std::cout << "\x1b[2J\x1b[H";
      run_once(snap);
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Snapshot snap;
  if (!load_snapshot(snap, file, demo)) { std::cerr << "error: cannot read IPv6 route sources\n"; return 1; }
  run_once(snap);
  return 0;
}