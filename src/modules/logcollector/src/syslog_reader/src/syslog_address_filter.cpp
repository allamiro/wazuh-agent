#include "syslog_reader.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <string>
#include <vector>

// This file deliberately contains no coroutines. The Boost.Asio network template
// instantiations below trigger an internal compiler error on GCC 11 when compiled
// in the same translation unit as the SyslogReader coroutines, so the source
// allow-list matching is isolated here.

using namespace logcollector;

namespace
{
    /// @brief Checks whether a source address matches a single allow-list entry (host or CIDR)
    bool AddressMatchesEntry(const boost::asio::ip::address& address, const std::string& entry)
    {
        boost::system::error_code ec;
        const auto slash = entry.find('/');

        if (slash == std::string::npos)
        {
            // Plain host address: exact match.
            const auto allowed = boost::asio::ip::make_address(entry, ec);
            return !ec && allowed == address;
        }

        // CIDR network: compare the address's network (same prefix) against the entry's network.
        if (address.is_v4())
        {
            const auto net = boost::asio::ip::make_network_v4(entry, ec);
            if (ec)
            {
                return false;
            }
            const auto prefix = static_cast<unsigned short>(net.prefix_length());
            return boost::asio::ip::network_v4(address.to_v4(), prefix).canonical() == net.canonical();
        }

        const auto net = boost::asio::ip::make_network_v6(entry, ec);
        if (ec)
        {
            return false;
        }
        const auto prefix = static_cast<unsigned short>(net.prefix_length());
        return boost::asio::ip::network_v6(address.to_v6(), prefix).canonical() == net.canonical();
    }
} // namespace

bool SyslogReader::IsAddressAllowed(const std::vector<std::string>& allowedIps,
                                    const boost::asio::ip::address& address)
{
    if (allowedIps.empty())
    {
        return true;
    }

    return std::any_of(allowedIps.begin(),
                       allowedIps.end(),
                       [&address](const std::string& entry) { return AddressMatchesEntry(address, entry); });
}
