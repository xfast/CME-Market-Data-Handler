/*
 * pcap_dump.cpp
 *
 * Dumps all decoded MDP3 messages from a pcap file with full field details.
 * Useful for debugging and inspecting raw market data content.
 *
 * Build:
 *   g++ -DUSE_PCAP=true pcap_dump.cpp -O2 -pthread -lpcap -o pcap_dump
 *
 * Usage:
 *   ./pcap_dump <pcap_file>
 */

#include "CallBackIF.hpp"
#include "MessageProcessor.hpp"

#include <cstring>
#include <iomanip>
#include <ctime>

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

static const char *side_str(char side)
{
    switch (side) {
        case '0': case 0: return "Buy";
        case '1': case 1: return "Sell";
        default: return "?";
    }
}

static const char *update_action_str(uint8_t action)
{
    switch (action) {
        case 0: return "New";
        case 1: return "Change";
        case 2: return "Delete";
        case 3: return "DeleteThru";
        case 4: return "DeleteFrom";
        case 5: return "Overlay";
        default: return "Unknown";
    }
}

static uint64_t msg_count = 0;

struct DumpCallback : public m2tech::mdp3::CallBackIF
{
    void MDIncrementalRefreshBook(
        uint64_t recv_time,
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        uint32_t securityID,
        int64_t px_mantissa,
        int8_t px_exponent,
        char side,
        int32_t sz,
        int32_t numorders,
        uint8_t pxlevel,
        bool endOfEvent,
        bool recovery) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] MBP Book Update"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  px=" << std::fixed << std::setprecision(6) << to_price(px_mantissa, px_exponent)
                  << "  side=" << side_str(side)
                  << "  sz=" << sz
                  << "  orders=" << numorders
                  << "  level=" << (int)pxlevel
                  << "  eoe=" << endOfEvent
                  << "  recovery=" << recovery
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

    void MDIncrementalRefreshBook(
        uint64_t recv_time,
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        uint32_t securityID,
        int64_t px_mantissa,
        int8_t px_exponent,
        char side,
        int32_t displayQty,
        uint64_t orderID,
        uint8_t orderUpdateAction,
        uint64_t priority,
        bool endOfEvent,
        bool recovery) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] MBO Book Update"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  px=" << std::fixed << std::setprecision(6) << to_price(px_mantissa, px_exponent)
                  << "  side=" << side_str(side)
                  << "  qty=" << displayQty
                  << "  oid=" << orderID
                  << "  action=" << update_action_str(orderUpdateAction)
                  << "  prio=" << priority
                  << "  eoe=" << endOfEvent
                  << "  recovery=" << recovery
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
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
        msg_count++;
        std::cout << "[" << msg_count << "] Trade (MBP)"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  px=" << std::fixed << std::setprecision(6) << to_price(px_mantissa, px_exponent)
                  << "  qty=" << sz
                  << "  aggr=" << (aggressor_side == 1 ? "Buy" : aggressor_side == 2 ? "Sell" : "N/A")
                  << "  orders=" << numorders
                  << "  last=" << lastTrade
                  << "  eoe=" << endofEvent
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

    void MDIncrementalRefreshTradeSummary(
        uint64_t recv_time,
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        int32_t lastQty,
        uint64_t orderID,
        bool lastTrade,
        bool endofEvent) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] Trade (MBO)"
                  << "  seq=" << msgSeqNum
                  << "  qty=" << lastQty
                  << "  oid=" << orderID
                  << "  last=" << lastTrade
                  << "  eoe=" << endofEvent
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

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
        msg_count++;
        std::cout << "[" << msg_count << "] Session Statistics"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << secid
                  << "  px=" << std::fixed << std::setprecision(6) << to_price(px_mantissa, px_exponent)
                  << "  flag=" << (int)openCloseSettleFlag
                  << "  action=" << update_action_str(updateAction)
                  << "  type=" << entryType
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

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
        msg_count++;
        std::cout << "[" << msg_count << "] Instrument Definition"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << sec_id
                  << "  sym=" << trim(sym)
                  << "  asset=" << trim(asset, 6)
                  << "  cfi=" << trim(cfiCode, 6)
                  << "  group=" << trim(sec_group, 6)
                  << "  seg=" << (int)seg_id
                  << "  status=" << (int)tradingStatus
                  << "  hlimit=" << std::fixed << std::setprecision(2) << to_price(high_limit_px_mantissa, high_limit_px_exponent)
                  << "  llimit=" << to_price(low_limit_px_mantissa, low_limit_px_exponent)
                  << "  time=" << format_nanos(sendingTime)
                  << "\n";
    }

    void ChannelReset(
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        const char *mdEntryType) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] Channel Reset"
                  << "  seq=" << msgSeqNum
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

    void SnapshotFullRefreshOrderBook(
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        uint32_t currentChunk,
        uint32_t numChunks,
        int32_t securityID,
        int32_t displayQty,
        int64_t px_mantissa,
        int64_t px_exponent,
        char side,
        uint64_t orderPriority,
        uint64_t orderID) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] Snapshot OrderBook"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  px=" << std::fixed << std::setprecision(6) << to_price(px_mantissa, px_exponent)
                  << "  side=" << side_str(side)
                  << "  qty=" << displayQty
                  << "  oid=" << orderID
                  << "  chunk=" << currentChunk << "/" << numChunks
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

    void MDIncrementalRefreshLimitsBanding(
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        int32_t securityID,
        int64_t pxh_mantissa,
        int8_t pxh_exponent,
        int64_t pxl_mantissa,
        int8_t pxl_exponent,
        int64_t pxvar_mantissa,
        int8_t pxvar_exponent,
        const char *entryType) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] Limits Banding"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  high=" << std::fixed << std::setprecision(2) << to_price(pxh_mantissa, pxh_exponent)
                  << "  low=" << to_price(pxl_mantissa, pxl_exponent)
                  << "  var=" << to_price(pxvar_mantissa, pxvar_exponent)
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

    void SecurityStatus(
        uint32_t msgSeqNum,
        uint64_t transactTime,
        uint64_t sendingTime,
        int32_t securityID,
        uint8_t haltReason,
        uint8_t tradingStatus,
        uint8_t tradingEvent) noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] Security Status"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  halt=" << (int)haltReason
                  << "  status=" << (int)tradingStatus
                  << "  event=" << (int)tradingEvent
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
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
        msg_count++;
        std::cout << "[" << msg_count << "] Volume"
                  << "  seq=" << msgSeqNum
                  << "  secid=" << securityID
                  << "  vol=" << volume
                  << "  type=" << typ
                  << "  action=" << update_action_str(action)
                  << "  time=" << format_nanos(transactTime)
                  << "\n";
    }

    void Clear() noexcept override
    {
        msg_count++;
        std::cout << "[" << msg_count << "] *** CLEAR (gap detected) ***\n";
    }
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

    DumpCallback cb;
    m2tech::mdp3::MessageProcessor proc(&cb, false, argv[1]);
    proc.process_pcap_file();

    std::cout << "\n===== TOTAL MESSAGES: " << msg_count << " =====\n";

    return 0;
#endif
}
