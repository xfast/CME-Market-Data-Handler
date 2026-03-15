/*
 * trade_print.cpp
 *
 * Extracts and prints all trades from a CME MDP3 pcap file.
 * Displays trade price, quantity, aggressor side, and security ID
 * with a summary of total trades and volume.
 *
 * Build:
 *   g++ -DUSE_PCAP=true trade_print.cpp -O2 -pthread -lpcap -o trade_print
 *
 * Usage:
 *   ./trade_print <pcap_file>
 */

#include "CallBackIF.hpp"
#include "MessageProcessor.hpp"

#include <set>
#include <vector>
#include <cstring>
#include <iomanip>
#include <ctime>
#include <map>

struct TradeRecord {
    int32_t sec_id;
    double price;
    int32_t qty;
    uint8_t aggressor_side;
    uint64_t transact_time;
    uint64_t sending_time;
    uint32_t msg_seq_num;
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
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
    char result[80];
    snprintf(result, sizeof(result), "%s.%09lu", buf, frac);
    return result;
}

static const char *aggressor_str(uint8_t side)
{
    switch (side) {
        case 1: return "Buy";
        case 2: return "Sell";
        default: return "N/A";
    }
}

struct TradePrintCallback : public m2tech::mdp3::CallBackIF
{
    std::vector<TradeRecord> trades;
    std::map<int32_t, int64_t> volume_by_sec;

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
        TradeRecord rec;
        rec.sec_id = securityID;
        rec.price = to_price(px_mantissa, px_exponent);
        rec.qty = sz;
        rec.aggressor_side = aggressor_side;
        rec.transact_time = transactTime;
        rec.sending_time = sendingTime;
        rec.msg_seq_num = msgSeqNum;
        trades.push_back(rec);
        volume_by_sec[securityID] += sz;
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
        uint64_t, bool, bool) noexcept override {}

    void MDIncrementalRefreshSessionStatistics(
        uint32_t, uint64_t, uint64_t, uint32_t, uint8_t,
        int64_t, int64_t, uint8_t, char) noexcept override {}

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

    TradePrintCallback cb;
    m2tech::mdp3::MessageProcessor proc(&cb, false, argv[1]);
    proc.process_pcap_file();

    // Print header
    std::cout << std::left
              << std::setw(18) << "Time"
              << std::setw(12) << "SecID"
              << std::setw(16) << "Price"
              << std::setw(10) << "Qty"
              << std::setw(8)  << "Side"
              << std::setw(12) << "SeqNum"
              << std::endl;

    std::cout << std::string(76, '-') << std::endl;

    for (const auto &t : cb.trades)
    {
        std::cout << std::left
                  << std::setw(18) << format_nanos(t.transact_time)
                  << std::setw(12) << t.sec_id
                  << std::setw(16) << std::fixed << std::setprecision(2) << t.price
                  << std::setw(10) << t.qty
                  << std::setw(8)  << aggressor_str(t.aggressor_side)
                  << std::setw(12) << t.msg_seq_num
                  << std::endl;
    }

    // Summary
    int64_t total_volume = 0;
    for (const auto &kv : cb.volume_by_sec)
        total_volume += kv.second;

    std::cout << "\n===== SUMMARY =====\n";
    std::cout << "Total trades:     " << cb.trades.size() << std::endl;
    std::cout << "Total volume:     " << total_volume << std::endl;
    std::cout << "Unique securities: " << cb.volume_by_sec.size() << std::endl;

    if (!cb.trades.empty())
    {
        std::cout << "First trade at:   " << format_nanos(cb.trades.front().transact_time) << std::endl;
        std::cout << "Last trade at:    " << format_nanos(cb.trades.back().transact_time) << std::endl;
    }

    // Volume by security
    if (!cb.volume_by_sec.empty())
    {
        std::cout << "\n--- Volume by Security ---\n";
        std::cout << std::left << std::setw(12) << "SecID" << "Volume" << std::endl;
        std::cout << std::string(30, '-') << std::endl;
        for (const auto &kv : cb.volume_by_sec)
        {
            std::cout << std::left << std::setw(12) << kv.first << kv.second << std::endl;
        }
    }

    return 0;
#endif
}
