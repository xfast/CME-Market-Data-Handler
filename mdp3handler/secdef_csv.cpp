/*
 * secdef_csv.cpp
 *
 * Extracts security definitions (futures and options on futures) from a
 * CME MDP3 pcap file and writes them to CSV. Supports filtering by
 * underlying symbol (e.g. "ES", "NQ", "CL") and instrument type.
 *
 * Decodes both template 54 (MDInstrumentDefinitionFuture) and
 * template 55 (MDInstrumentDefinitionOption) directly from the pcap,
 * without requiring changes to the core callback interface.
 *
 * Build:
 *   g++ -DUSE_PCAP=true secdef_csv.cpp -O2 -pthread -lpcap -o secdef_csv
 *
 * Usage:
 *   ./secdef_csv <pcap_file>                       # all definitions to stdout
 *   ./secdef_csv <pcap_file> -o output.csv         # write to file
 *   ./secdef_csv <pcap_file> -s ES                 # filter by symbol/asset "ES"
 *   ./secdef_csv <pcap_file> -s ES -t futures      # futures only
 *   ./secdef_csv <pcap_file> -s ES -t options      # options on futures only
 *   ./secdef_csv <pcap_file> -s ES -t all          # both (default)
 */

#include <pcap.h>

#include "mktdata/MDInstrumentDefinitionFuture54.h"
#include "mktdata/MDInstrumentDefinitionOption55.h"
#include "mktdata/MessageHeader.h"
#include "mktdata/PutOrCall.h"

#include <cstdint>
#include <cstring>
#include <cmath>
#include <ctime>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>

// ---- helpers ----

static double to_price(int64_t mantissa, int8_t exponent)
{
    return double(mantissa) * std::pow(10.0, double(exponent));
}

static std::string trim(const char *s, size_t maxlen)
{
    std::string str(s, strnlen(s, maxlen));
    while (!str.empty() && str.back() == ' ')
        str.pop_back();
    return str;
}

static std::string format_nanos(uint64_t nanos)
{
    if (nanos == 0)
        return "";
    time_t secs = nanos / 1000000000ULL;
    uint64_t frac = nanos % 1000000000ULL;
    struct tm tm;
    gmtime_r(&secs, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    char result[80];
    snprintf(result, sizeof(result), "%s.%09lu", buf, frac);
    return result;
}

static std::string csv_escape(const std::string &s)
{
    if (s.find(',') == std::string::npos && s.find('"') == std::string::npos)
        return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

// ---- data ----

enum class InstrumentType { Future, Option };

struct SecDefRecord {
    InstrumentType type;
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
    // option-specific
    std::string put_or_call;   // "Put", "Call", or ""
    double strike_price;       // 0 if not option
    std::string underlying;    // underlying symbol for options
};

// ---- pcap + SBE decoding ----

static std::vector<SecDefRecord> records;

static void decode_packet(const unsigned char *packet, int len)
{
    // Skip Ethernet (14) + IP (variable) + UDP (8)
    packet += 14;
    len -= 14;
    int ip_header_len = (*packet & 0x0F) * 4;
    packet += ip_header_len;
    len -= ip_header_len;
    packet += 8;
    len -= 8;

    if (len <= 0)
        return;

    constexpr size_t sbe_header_size = 10;

    auto *data = (char *)packet;
    auto data_start = data;

    // MDP3 packet header
    // uint32_t MsgSeqNum
    data += sizeof(uint32_t);
    // uint64_t SendingTime
    auto SendingTime = *(uint64_t *)(data);
    data += sizeof(uint64_t);

    while (size_t(data - data_start) < (size_t)len)
    {
        if (size_t(data - data_start) + sbe_header_size > (size_t)len)
            break;

        auto MsgSize = *(uint16_t *)(data);
        data += sizeof(uint16_t);
        auto BlockLength = *(uint16_t *)(data);
        data += sizeof(uint16_t);
        auto template_id = *(uint16_t *)(data);
        data += sizeof(uint16_t);
        auto SchemaID = *(uint16_t *)(data);
        data += sizeof(uint16_t);
        auto Version = *(uint16_t *)(data);
        data += sizeof(uint16_t);

        data -= sbe_header_size;

        if (template_id == 54)
        {
            mktdata::MDInstrumentDefinitionFuture54 def;
            def.wrapForDecode(data, sbe_header_size, BlockLength, Version, MsgSize);

            SecDefRecord rec;
            rec.type = InstrumentType::Future;
            rec.symbol = trim(def.symbol(), 20);
            rec.asset = trim(def.asset(), 6);
            rec.cfi_code = trim(def.cFICode(), 6);
            rec.sec_group = trim(def.securityGroup(), 6);
            rec.sec_id = def.securityID();
            rec.seg_id = def.marketSegmentID();
            rec.trading_status = def.mDSecurityTradingStatus();
            rec.sending_time = SendingTime;
            rec.high_limit_px = to_price(def.highLimitPrice().mantissa(), def.highLimitPrice().exponent());
            rec.low_limit_px = to_price(def.lowLimitPrice().mantissa(), def.lowLimitPrice().exponent());
            rec.put_or_call = "";
            rec.strike_price = 0;
            rec.underlying = "";

            rec.activation = 0;
            rec.expiration = 0;
            auto events = def.noEvents();
            while (events.hasNext())
            {
                events.next();
                auto evid = events.eventType();
                if (evid == 5)
                    rec.activation = events.eventTime();
                else if (evid == 7)
                    rec.expiration = events.eventTime();
            }

            records.push_back(rec);
        }
        else if (template_id == 55)
        {
            mktdata::MDInstrumentDefinitionOption55 def;
            def.wrapForDecode(data, sbe_header_size, BlockLength, Version, MsgSize);

            SecDefRecord rec;
            rec.type = InstrumentType::Option;
            rec.symbol = trim(def.symbol(), 20);
            rec.asset = trim(def.asset(), 6);
            rec.cfi_code = trim(def.cFICode(), 6);
            rec.sec_group = trim(def.securityGroup(), 6);
            rec.sec_id = def.securityID();
            rec.seg_id = def.marketSegmentID();
            rec.trading_status = def.mDSecurityTradingStatus();
            rec.sending_time = SendingTime;
            rec.high_limit_px = to_price(def.highLimitPrice().mantissa(), def.highLimitPrice().exponent());
            rec.low_limit_px = to_price(def.lowLimitPrice().mantissa(), def.lowLimitPrice().exponent());
            rec.strike_price = to_price(def.strikePrice().mantissa(), def.strikePrice().exponent());

            auto pc = def.putOrCall();
            if (pc == mktdata::PutOrCall::Put)
                rec.put_or_call = "Put";
            else if (pc == mktdata::PutOrCall::Call)
                rec.put_or_call = "Call";
            else
                rec.put_or_call = "";

            rec.activation = 0;
            rec.expiration = 0;
            auto events = def.noEvents();
            while (events.hasNext())
            {
                events.next();
                auto evid = events.eventType();
                if (evid == 5)
                    rec.activation = events.eventTime();
                else if (evid == 7)
                    rec.expiration = events.eventTime();
            }

            // Get underlying symbol from NoUnderlyings group
            rec.underlying = "";
            auto underlyings = def.noUnderlyings();
            if (underlyings.hasNext())
            {
                underlyings.next();
                rec.underlying = trim(underlyings.underlyingSymbol(), 20);
            }

            records.push_back(rec);
        }

        data += MsgSize;
    }
}

// ---- CSV output ----

static void write_csv(std::ostream &out, const std::vector<SecDefRecord> &recs)
{
    out << "Type,SecID,Symbol,Asset,CFICode,SecGroup,SegID,TradingStatus,"
        << "HighLimitPx,LowLimitPx,PutCall,StrikePrice,Underlying,"
        << "Activation,Expiration,SendingTime\n";

    for (const auto &r : recs)
    {
        out << (r.type == InstrumentType::Future ? "Future" : "Option") << ","
            << r.sec_id << ","
            << csv_escape(r.symbol) << ","
            << csv_escape(r.asset) << ","
            << csv_escape(r.cfi_code) << ","
            << csv_escape(r.sec_group) << ","
            << (int)r.seg_id << ","
            << (int)r.trading_status << ","
            << std::fixed << std::setprecision(2) << r.high_limit_px << ","
            << r.low_limit_px << ","
            << r.put_or_call << ","
            << (r.strike_price != 0 ? std::to_string(r.strike_price) : "") << ","
            << csv_escape(r.underlying) << ","
            << format_nanos(r.activation) << ","
            << format_nanos(r.expiration) << ","
            << format_nanos(r.sending_time) << "\n";
    }
}

// ---- main ----

static void usage(const char *prog)
{
    std::cerr << "Usage: " << prog << " <pcap_file> [options]\n"
              << "\nOptions:\n"
              << "  -o <file>     Write CSV to file (default: stdout)\n"
              << "  -s <symbol>   Filter by symbol or asset (case-insensitive substring match)\n"
              << "  -t <type>     Filter by type: futures, options, or all (default: all)\n"
              << "\nExamples:\n"
              << "  " << prog << " data.pcap\n"
              << "  " << prog << " data.pcap -o secdefs.csv\n"
              << "  " << prog << " data.pcap -s ES -t futures\n"
              << "  " << prog << " data.pcap -s ES -t options\n"
              << "  " << prog << " data.pcap -s CL -o cl_instruments.csv\n";
}

static bool icase_contains(const std::string &haystack, const std::string &needle)
{
    if (needle.empty())
        return true;
    std::string h = haystack, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    std::string pcap_file = argv[1];
    std::string output_file;
    std::string symbol_filter;
    std::string type_filter = "all";

    for (int i = 2; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "-s" && i + 1 < argc) {
            symbol_filter = argv[++i];
        } else if (arg == "-t" && i + 1 < argc) {
            type_filter = argv[++i];
            std::transform(type_filter.begin(), type_filter.end(), type_filter.begin(), ::tolower);
            if (type_filter != "futures" && type_filter != "options" && type_filter != "all") {
                std::cerr << "Error: -t must be 'futures', 'options', or 'all'\n";
                return 1;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            usage(argv[0]);
            return 1;
        }
    }

    // Read pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!handle)
    {
        std::cerr << "Error opening pcap: " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr header;
    const unsigned char *packet;
    while ((packet = pcap_next(handle, &header)))
    {
        decode_packet(packet, header.len);
    }
    pcap_close(handle);

    // Apply filters
    std::vector<SecDefRecord> filtered;
    for (const auto &r : records)
    {
        // Type filter
        if (type_filter == "futures" && r.type != InstrumentType::Future)
            continue;
        if (type_filter == "options" && r.type != InstrumentType::Option)
            continue;

        // Symbol filter: match against symbol, asset, underlying, or sec_group
        if (!symbol_filter.empty())
        {
            if (!icase_contains(r.symbol, symbol_filter) &&
                !icase_contains(r.asset, symbol_filter) &&
                !icase_contains(r.underlying, symbol_filter) &&
                !icase_contains(r.sec_group, symbol_filter))
                continue;
        }

        filtered.push_back(r);
    }

    // Deduplicate by sec_id (keep last definition seen)
    std::map<int32_t, size_t> last_by_id;
    for (size_t i = 0; i < filtered.size(); i++)
        last_by_id[filtered[i].sec_id] = i;

    std::vector<SecDefRecord> deduped;
    for (const auto &kv : last_by_id)
        deduped.push_back(filtered[kv.second]);

    // Output
    if (output_file.empty())
    {
        write_csv(std::cout, deduped);
    }
    else
    {
        std::ofstream ofs(output_file);
        if (!ofs)
        {
            std::cerr << "Error: cannot open " << output_file << " for writing\n";
            return 1;
        }
        write_csv(ofs, deduped);
        ofs.close();
        std::cerr << "Wrote " << deduped.size() << " records to " << output_file << std::endl;
    }

    // Summary to stderr
    int futures_count = 0, options_count = 0;
    for (const auto &r : deduped) {
        if (r.type == InstrumentType::Future) futures_count++;
        else options_count++;
    }
    std::cerr << "Total: " << deduped.size() << " definitions"
              << " (" << futures_count << " futures, " << options_count << " options)";
    if (!symbol_filter.empty())
        std::cerr << " matching '" << symbol_filter << "'";
    std::cerr << std::endl;

    return 0;
}
