/*
 * stats_extract.cpp
 *
 * Extracts session statistics from a CME MDP3 pcap file.
 * Collects open, high, low, settle prices and volume data
 * per security and prints a summary table.
 *
 * Build:
 *   g++ -DUSE_PCAP=true stats_extract.cpp -O2 -pthread -lpcap -o stats_extract
 *
 * Usage:
 *   ./stats_extract <pcap_file>
 */

#include "CallBackIF.hpp"
#include "MessageProcessor.hpp"

#include <map>
#include <cstring>
#include <iomanip>
#include <ctime>
#include <cfloat>

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

struct SecurityStats {
    double open = 0;
    double high = 0;
    double low = 0;
    double settle = 0;
    int32_t volume = 0;
    int32_t trade_count = 0;
    bool has_open = false;
    bool has_high = false;
    bool has_low = false;
    bool has_settle = false;
    uint64_t first_time = UINT64_MAX;
    uint64_t last_time = 0;
};

struct StatsCallback : public m2tech::mdp3::CallBackIF
{
    std::map<uint32_t, SecurityStats> stats;

    void MDIncrementalRefreshSessionStatistics(
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        uint32_t secid,
        uint8_t openCloseSettleFlag,
        int64_t px_mantissa,
        int64_t px_exponent,
        uint8_t updateAction,
        char entryType) noexcept override
    {
        auto &s = stats[secid];
        double px = to_price(px_mantissa, px_exponent);

        if (transactTime < s.first_time)
            s.first_time = transactTime;
        if (transactTime > s.last_time)
            s.last_time = transactTime;

        // entryType: '4'=Open, '7'=High, '8'=Low, '6'=Settle
        switch (entryType)
        {
            case '4':
                s.open = px;
                s.has_open = true;
                break;
            case '7':
                s.high = px;
                s.has_high = true;
                break;
            case '8':
                s.low = px;
                s.has_low = true;
                break;
            case '6':
                s.settle = px;
                s.has_settle = true;
                break;
        }
    }

    void MDIncrementalRefreshTradeSummary(
        uint64_t recv_time,
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        int32_t securityID,
        int64_t px_mantissa,
        int8_t px_exponent,
        char side,
        uint8_t aggressor_side,
        int32_t sz,
        int32_t numorders,
        bool lastTrade,
        bool endofEvent) noexcept override
    {
        auto &s = stats[securityID];
        s.volume += sz;
        s.trade_count++;
    }

    void MDIncrementalRefreshVolume(
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        int32_t securityID,
        int32_t volume,
        char typ,
        uint8_t action) noexcept override
    {
        auto &s = stats[securityID];
        s.volume = volume;
    }

    // --- stubs ---

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
        uint64_t, bool, bool) noexcept override {}

    void MDInstrumentDefinitionFuture(
        uint32_t, uint64_t, char *, char *, char *,
        int64_t, int8_t, int64_t, int8_t, int64_t, int8_t,
        int32_t, char, uint8_t, uint64_t, uint64_t,
        char *, uint8_t) noexcept override {}

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

    void Clear() noexcept override {}
};

static std::string fmt_px(double px, bool valid)
{
    if (!valid)
        return "-";
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f", px);
    return buf;
}

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

    StatsCallback cb;
    m2tech::mdp3::MessageProcessor proc(&cb, false, argv[1]);
    proc.process_pcap_file();

    // Print header
    std::cout << std::left
              << std::setw(12) << "SecID"
              << std::setw(16) << "Open"
              << std::setw(16) << "High"
              << std::setw(16) << "Low"
              << std::setw(16) << "Settle"
              << std::setw(12) << "Volume"
              << std::setw(10) << "Trades"
              << std::endl;

    std::cout << std::string(98, '-') << std::endl;

    int total_securities = 0;
    int64_t total_volume = 0;
    int64_t total_trades = 0;

    for (const auto &kv : cb.stats)
    {
        const auto &s = kv.second;
        // Only print securities that have at least some data
        if (!s.has_open && !s.has_high && !s.has_low && !s.has_settle && s.trade_count == 0)
            continue;

        total_securities++;
        total_volume += s.volume;
        total_trades += s.trade_count;

        std::cout << std::left
                  << std::setw(12) << kv.first
                  << std::setw(16) << fmt_px(s.open, s.has_open)
                  << std::setw(16) << fmt_px(s.high, s.has_high)
                  << std::setw(16) << fmt_px(s.low, s.has_low)
                  << std::setw(16) << fmt_px(s.settle, s.has_settle)
                  << std::setw(12) << s.volume
                  << std::setw(10) << s.trade_count
                  << std::endl;
    }

    std::cout << "\n===== SUMMARY =====\n";
    std::cout << "Securities with data: " << total_securities << std::endl;
    std::cout << "Total volume:         " << total_volume << std::endl;
    std::cout << "Total trades:         " << total_trades << std::endl;

    return 0;
#endif
}
