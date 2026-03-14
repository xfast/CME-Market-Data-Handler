# CME-Market-Data-Handler

A minimalist CME MDP 3.0 C++ market data feed handler (and pcap file reader) implementing all required features needed to certify on CME AutoCert. It is tested/certified on futures but with minor modifications will work for spreads, options, BTEC, and EBS.

Latency from packet reception to application callback invocation is under 1 microsecond.

For the full project documentation and blog post, see: https://m2te.ch/blog/opensource/cme-mdp3

## Overview

This library consumes real-time futures market data from the CME Group via UDP multicast, decodes the binary SBE (Simple Binary Encoding) messages, and delivers parsed data to your application through callbacks. It supports both live multicast feeds and recorded pcap file replay.

**Supported data types:**

- Market-by-Price (MBP) and Market-by-Order (MBO) book updates
- Trade summaries
- Session statistics (open, high, low, settle, volume)
- Instrument definitions
- Price limits and banding
- Security status and trading halts

## Architecture

```
CME Multicast (Channel A & B)
         |
   UDP Sockets
         |
  MessageProcessor ──── gap detected ───> RecoveryProcessor
         |                                       |
    DataDecoder                            Snapshot/Instrument
         |                                   Recovery
   CallBackIF (your code)  <─── recovery complete
```

- **MessageProcessor** — Receives UDP packets on dual-redundant channels, sequences messages, detects gaps
- **DataDecoder** — Parses binary SBE wire format into typed C++ structs
- **RecoveryProcessor** — Handles gap recovery from CME snapshot/instrument recovery channels
- **CallBackIF** — Abstract interface you subclass to receive parsed market data events

## Prerequisites

- Linux (tested on CentOS, will not work on Windows)
- GCC 8.5+ with C++11 support
- `libpcap-dev` (optional, for pcap file support)

```bash
# Install pcap support (optional)
sudo apt-get install libpcap-dev
```

## Building

```bash
cd mdp3handler

# Basic build (live multicast only)
g++ main.cpp -O2 -pthread -o mdp3handler

# Build with pcap file support
g++ -DUSE_PCAP=true main.cpp -O2 -pthread -lpcap -o mdp3handler

# Debug build
g++ -DUSE_PCAP=true main.cpp -O0 -g -pthread -lpcap -o mdp3handler
```

## Quick Start

### 1. Implement Your Callbacks

Edit `CallBackImpl.hpp` (or create a subclass of `CallBackIF`) and fill in the callback methods with your business logic:

```cpp
#include "CallBackIF.hpp"

class MyHandler : public CallBackIF {
public:
    void MDIncrementalRefreshBook(
        int32_t secid,
        uint32_t rptseq,
        const mktdata::MDEntryTypeBook::Value &entry_type,
        const mktdata::MDUpdateAction::Value &action,
        int32_t level,
        double px,
        int32_t qty,
        int32_t numorders,
        uint64_t prio) override
    {
        // Build and maintain your order book here
        std::cout << "Book update: secid=" << secid
                  << " px=" << px << " qty=" << qty << "\n";
    }

    void MDIncrementalRefreshTradeSummary(
        int32_t secid,
        uint32_t rptseq,
        double px,
        int32_t qty,
        int32_t numorders,
        const mktdata::MDUpdateAction::Value &action,
        uint64_t orderid) override
    {
        // Process trade events here
        std::cout << "Trade: secid=" << secid
                  << " px=" << px << " qty=" << qty << "\n";
    }

    void Clear(int32_t secid) override {
        // Gap detected — clear your order book for this security
    }
};
```

See `CallBackIF.hpp` for the full list of overridable callbacks.

### 2a. Run with Live Multicast

Configure the multicast addresses and ports from your CME channel assignment:

```cpp
#include "CallBackImpl.hpp"
#include "MessageProcessor.hpp"
#include "RecoveryProcessor.hpp"
#include <thread>

int main() {
    MyHandler handler;

    // Multicast parameters (from CME channel config)
    m2tech::mdp3::MessageProcessor msg_proc(
        &handler,
        14344,              // port_a (incremental feed A)
        15344,              // port_b (incremental feed B)
        "233.158.8.17",     // group_a
        "233.158.8.144",    // group_b
        "10.248.146.89",    // network interface
        true,               // enable recovery
        true,               // recover on startup
        true);              // debug output

    m2tech::mdp3::RecoveryProcessor<m2tech::mdp3::MessageProcessor> rec_proc(
        &msg_proc,
        &handler,
        21344,              // port_dr (data recovery)
        6344,               // port_ir (instrument recovery)
        "224.0.25.191",     // group_dr
        "233.158.8.101",    // group_ir
        "10.248.146.89",    // network interface
        true);              // debug output

    msg_proc.set_recovery_processor(&rec_proc);
    msg_proc.connect();

    std::thread msg_thread(std::ref(msg_proc));
    std::thread rec_thread(std::ref(rec_proc));

    msg_thread.join();
    rec_thread.join();
}
```

### 2b. Run with a Pcap File

For testing and development, replay a recorded capture file:

```cpp
#include "CallBackImpl.hpp"
#include "MessageProcessor.hpp"

int main(int argc, char *argv[]) {
    MyHandler handler;

    m2tech::mdp3::MessageProcessor msg_proc(
        &handler,
        true,           // debug output
        argv[1]);       // pcap filename

    msg_proc.process_pcap_file();
}
```

```bash
# Compile with pcap support and run
g++ -DUSE_PCAP=true main.cpp -O2 -pthread -lpcap -o mdp3handler
./mdp3handler capture.pcap
```

## Key Callbacks

| Callback | Description |
|---|---|
| `MDIncrementalRefreshBook` | MBP/MBO book updates (add/change/delete price levels or orders) |
| `MDIncrementalRefreshTradeSummary` | Trade executions |
| `MDIncrementalRefreshSessionStatistics` | Open, high, low, settle prices |
| `MDInstrumentDefinitionFuture` | Instrument/contract definitions |
| `SnapshotFullRefreshOrderBook` | Full order book snapshots (during recovery) |
| `MDIncrementalRefreshLimitsBanding` | Price limit bands |
| `SecurityStatus` | Trading halts and security status changes |
| `MDIncrementalRefreshVolume` | Volume updates |
| `ChannelReset` | Channel reset — clear all book state |
| `Clear` | Gap detected — clear book state for a security |

## Price Conversion

CME sends prices as mantissa + exponent pairs. Use the provided helper:

```cpp
// In your callback:
double price = to_price(mantissa, exponent);
```

## Project Structure

```
mdp3handler/
├── main.cpp                 # Example entry point
├── CallBackIF.hpp           # Abstract callback interface (subclass this)
├── CallBackImpl.hpp         # Empty callback implementation template
├── MessageProcessor.hpp     # Main message processor (live + pcap)
├── DataDecoder.hpp          # SBE binary message decoder
├── RecoveryProcessor.hpp    # Gap detection and recovery
├── udp_socket.hpp           # UDP multicast socket utilities
├── message_buffer.hpp       # Message buffer structure
└── mktdata/                 # Auto-generated SBE message type headers (73 files)
```

## License

MIT License. Copyright 2022 Vincent Maciejewski, Quant Enterprises & M2 Tech.

Contact: v@m2te.ch | mayeski@gmail.com | https://m2te.ch/
