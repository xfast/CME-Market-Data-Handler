/*
 * secdef_extract.cpp
 *
 * Extracts security definitions from a CME MDP3 pcap file.
 * Prints each instrument found and a summary of total unique securities
 * with the time range they were defined.
 *
 * Build:
 *   g++ -DUSE_PCAP=true secdef_extract.cpp -O2 -pthread -lpcap -o secdef_extract
 *
 * Usage:
 *   ./secdef_extract <pcap_file>
 */

#include "CallBackIF.hpp"
#include "MessageProcessor.hpp"

#include <set>
#include <vector>
#include <cstring>
#include <iomanip>
#include <ctime>
#include <algorithm>

struct SecurityDef {
    int32_t sec_id;
    std::string symbol;
    std::string asset;
    std::string cfi_code;
    std::string sec_group;
    uint8_t seg_id;
    uint8_t trading_status;
    uint64_t sending_time;
    uint64_t activation;
    uint64_t expiration;
    double high_limit_px;
    double low_limit_px;
};

static std::string format_nanos(uint64_t nanos)
{
    if (nanos == 0)
        return "N/A";
    time_t secs = nanos / 1000000000ULL;
    uint64_t frac = nanos % 1000000000ULL;
    struct tm tm;
    gmtime_r(&secs, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    char result[80];
    snprintf(result, sizeof(result), "%s.%09lu UTC", buf, frac);
    return result;
}

static std::string trim(const char *s, size_t maxlen = 20)
{
    std::string str(s, strnlen(s, maxlen));
    while (!str.empty() && str.back() == ' ')
        str.pop_back();
    return str;
}

struct SecDefCallback : public m2tech::mdp3::CallBackIF
{
    std::vector<SecurityDef> definitions;
    std::set<int32_t> seen_ids;

    void MDInstrumentDefinitionFuture(
        uint32_t msgSeqNum,
        uint64_t sendingTime,
        char *sym,
        char *asset,
        char *cfiCode,
        int64_t high_limit_px_mantissa,
        int8_t high_limit_px_exponent,
        int64_t low_limit_px_mantissa,
        int8_t low_limit_px_exponent,
        int64_t pxvar_mantissa,
        int8_t pxvar_exponent,
        int32_t sec_id,
        char updateAction,
        uint8_t tradingStatus,
        uint64_t activation,
        uint64_t expiration,
        char *sec_group,
        uint8_t seg_id) noexcept override
    {
        SecurityDef def;
        def.sec_id = sec_id;
        def.symbol = trim(sym);
        def.asset = trim(asset, 6);
        def.cfi_code = trim(cfiCode, 6);
        def.sec_group = trim(sec_group, 6);
        def.seg_id = seg_id;
        def.trading_status = tradingStatus;
        def.sending_time = sendingTime;
        def.activation = activation;
        def.expiration = expiration;
        def.high_limit_px = to_price(high_limit_px_mantissa, high_limit_px_exponent);
        def.low_limit_px = to_price(low_limit_px_mantissa, low_limit_px_exponent);

        definitions.push_back(def);
        seen_ids.insert(sec_id);
    }

    // --- stubs for all other pure virtual callbacks ---

    void MDIncrementalRefreshBook(
        uint64_t, uint32_t, uint64_t, uint64_t, uint32_t,
        int64_t, int8_t, char, int32_t, int32_t, uint8_t,
        bool, bool) noexcept override {}

    void MDIncrementalRefreshBook(
        uint64_t, uint32_t, uint64_t, uint64_t, uint32_t,
        int64_t, int8_t, char, int32_t, uint64_t, uint8_t,
        uint64_t, bool, bool) noexcept override {}

    void MDIncrementalRefreshTradeSummary(
        uint64_t, uint32_t, uint64_t, uint64_t, int32_t,
        int64_t, int8_t, char, uint8_t, int32_t, int32_t,
        bool, bool) noexcept override {}

    void MDIncrementalRefreshTradeSummary(
        uint64_t, uint32_t, uint64_t, uint64_t, int32_t,
        uint64_t, bool, bool) noexcept override {}

    void MDIncrementalRefreshSessionStatistics(
        uint32_t, uint64_t, uint64_t, uint32_t, uint8_t,
        int64_t, int64_t, uint8_t, char) noexcept override {}

    void ChannelReset(
        uint32_t, uint64_t, uint64_t,
        const char *) noexcept override {}

    void SnapshotFullRefreshOrderBook(
        uint32_t, uint64_t, uint64_t, uint32_t, uint32_t,
        int32_t, int32_t, int64_t, int64_t, char,
        uint64_t, uint64_t) noexcept override {}

    void MDIncrementalRefreshLimitsBanding(
        uint32_t, uint64_t, uint64_t, int32_t,
        int64_t, int8_t, int64_t, int8_t,
        int64_t, int8_t, const char *) noexcept override {}

    void SecurityStatus(
        uint32_t, uint64_t, uint64_t, int32_t,
        uint8_t, uint8_t, uint8_t) noexcept override {}

    void MDIncrementalRefreshVolume(
        uint32_t, uint64_t, uint64_t, int32_t,
        int32_t, char, uint8_t) noexcept override {}

    void Clear() noexcept override {}
};

int main(int argc, char *argv[])
{
#ifndef USE_PCAP
    std::cerr << "Error: must be compiled with -DUSE_PCAP=true" << std::endl;
    return 1;
#else
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    SecDefCallback cb;
    m2tech::mdp3::MessageProcessor proc(&cb, false, argv[1]);
    proc.process_pcap_file();

    // Print each definition
    std::cout << std::left
              << std::setw(25) << "Symbol"
              << std::setw(10) << "SecID"
              << std::setw(8)  << "Asset"
              << std::setw(8)  << "Group"
              << std::setw(8)  << "CFI"
              << std::setw(18) << "HighLimit"
              << std::setw(18) << "LowLimit"
              << "SendingTime"
              << std::endl;

    std::cout << std::string(130, '-') << std::endl;

    for (const auto &d : cb.definitions)
    {
        std::cout << std::left
                  << std::setw(25) << d.symbol
                  << std::setw(10) << d.sec_id
                  << std::setw(8)  << d.asset
                  << std::setw(8)  << d.sec_group
                  << std::setw(8)  << d.cfi_code
                  << std::setw(18) << std::fixed << std::setprecision(2) << d.high_limit_px
                  << std::setw(18) << d.low_limit_px
                  << format_nanos(d.sending_time)
                  << std::endl;
    }

    // Summary
    uint64_t earliest = UINT64_MAX, latest = 0;
    for (const auto &d : cb.definitions)
    {
        if (d.sending_time > 0 && d.sending_time < earliest)
            earliest = d.sending_time;
        if (d.sending_time > latest)
            latest = d.sending_time;
    }

    std::cout << "\n===== SUMMARY =====\n";
    std::cout << "Total definition messages: " << cb.definitions.size() << std::endl;
    std::cout << "Unique securities:         " << cb.seen_ids.size() << std::endl;
    if (!cb.definitions.empty())
    {
        std::cout << "First definition at:       " << format_nanos(earliest) << std::endl;
        std::cout << "Last definition at:        " << format_nanos(latest) << std::endl;
    }

    return 0;
#endif
}
