// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <stdplus/net/addr/ip.hpp>
#include <stdplus/numeric/endian.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/conv.hpp>

#include "syslog.h"
#include <string>

namespace redfish
{
namespace ip_util
{

enum class Type
{
    GATEWAY4_ADDRESS,
    GATEWAY6_ADDRESS,
    IP4_ADDRESS,
    IP6_ADDRESS,
    SUBNETMASK
};

/**
 * @brief Converts boost::asio::ip::address to string
 * Will automatically convert IPv4-mapped IPv6 address back to IPv4.
 *
 * @param[in] ipAddr IP address to convert
 *
 * @return IP address string
 */
inline std::string toString(const boost::asio::ip::address& ipAddr)
{
    if (ipAddr.is_v6() && ipAddr.to_v6().is_v4_mapped())
    {
        return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped,
                                                ipAddr.to_v6())
            .to_string();
    }
    return ipAddr.to_string();
}

/**
 * @brief Helper function that verifies IP address to check if it is in
 *        proper format. If bits pointer is provided, also calculates active
 *        bit count for Subnet Mask.
 *
 * @param[in]  ip     IP that will be verified
 * @param[out] bits   Calculated mask in bits notation
 *
 * @return true in case of success, false otherwise
 */
inline bool ipv4VerifyIpAndGetBitcount(const std::string& ip,
                                       uint8_t* prefixLength = nullptr)
{
    boost::system::error_code ec;
    boost::asio::ip::address_v4 addr = boost::asio::ip::make_address_v4(ip, ec);
    if (ec)
    {
        return false;
    }

    if (prefixLength != nullptr)
    {
        uint8_t prefix = 0;
        boost::asio::ip::address_v4::bytes_type maskBytes = addr.to_bytes();
        bool maskFinished = false;
        for (unsigned char byte : maskBytes)
        {
            if (maskFinished)
            {
                if (byte != 0U)
                {
                    return false;
                }
                continue;
            }
            switch (byte)
            {
                case 255:
                    prefix += 8;
                    break;
                case 254:
                    prefix += 7;
                    maskFinished = true;
                    break;
                case 252:
                    prefix += 6;
                    maskFinished = true;
                    break;
                case 248:
                    prefix += 5;
                    maskFinished = true;
                    break;
                case 240:
                    prefix += 4;
                    maskFinished = true;
                    break;
                case 224:
                    prefix += 3;
                    maskFinished = true;
                    break;
                case 192:
                    prefix += 2;
                    maskFinished = true;
                    break;
                case 128:
                    prefix += 1;
                    maskFinished = true;
                    break;
                case 0:
                    maskFinished = true;
                    break;
                default:
                    // Invalid netmask
                    return false;
            }
        }
        *prefixLength = prefix;
    }

    return true;
}

inline bool in6AddrIetfProtocolAssignment(in6_addr* addr)
{
    return (ntohl(addr->__in6_u.__u6_addr32[0]) >= 0x20010000 &&
            ntohl(addr->__in6_u.__u6_addr32[0]) <= 0x200101ff);
}
inline bool in6AddrDoc(in6_addr* addr)
{
    return ntohl(addr->__in6_u.__u6_addr32[0]) == 0x20010db8;
}

inline bool isSameSeries(std::string ipStr, std::string gwStr,
                         uint8_t prefixLength)
{
    auto ip = (stdplus::fromStr<stdplus::In4Addr>(ipStr)).a.s_addr;
    auto gw = (stdplus::fromStr<stdplus::In4Addr>(gwStr)).a.s_addr;
    auto netmask = htobe32(~UINT32_C(0) << (32 - prefixLength));

    if ((ip & netmask) != (gw & netmask))
    {
        return false;
    }

    return true;
}

static void isValidIPv6Addr(in6_addr* addr, Type type)
{
    std::string strType{"Gateway"};
    if (type == Type::IP6_ADDRESS)
    {
        strType = "IPv6";
        if (in6AddrIetfProtocolAssignment(addr))
        {
            throw std::invalid_argument(
                strType + " address is IETF Protocol Assignments.");
        }
        else if (in6AddrDoc(addr))
        {
            throw std::invalid_argument(strType + " address is Documentation.");
        }
        else if (IN6_IS_ADDR_LINKLOCAL(addr))
        {
            throw std::invalid_argument(strType + " address is Link-local.");
        }
    }

    if (IN6_IS_ADDR_LOOPBACK(addr))
    {
        throw std::invalid_argument(strType + " is Loopback.");
    }
    else if (IN6_IS_ADDR_MULTICAST(addr))
    {
        throw std::invalid_argument(strType + " is Multicast.");
    }
    else if (IN6_IS_ADDR_SITELOCAL(addr))
    {
        throw std::invalid_argument(strType + " is Sitelocal.");
    }
    else if (IN6_IS_ADDR_V4MAPPED(addr))
    {
        throw std::invalid_argument(strType + " is V4Mapped.");
    }
    else if (IN6_IS_ADDR_UNSPECIFIED(addr))
    {
        throw std::invalid_argument(strType + " is Unspecified.");
    }
}

inline bool validateIPv6address(std::string addr, Type type)
{
    try
    {
        std::optional<stdplus::InAnyAddr> Addrs;
        Addrs.emplace(stdplus::fromStr<stdplus::In6Addr>(addr));
        isValidIPv6Addr(reinterpret_cast<in6_addr*>(&Addrs.value()), type);
        return true;
    }
    catch (const std::exception& e)
    {
        syslog(LOG_WARNING, "validateIPv6address IP : %s is Invalid & Error Returned is : %s !!! \n", addr.c_str(), e.what());
        return false;
    }
}

inline std::string normalizeIPv6(const std::string& ipv6)
{
    try
    {
        boost::asio::ip::address_v6 addr(boost::asio::ip::make_address_v6(ipv6));
        return addr.to_string();
    }
    catch (const boost::system::system_error& e)
    {
        // Handle invalid IPv6 address format
        BMCWEB_LOG_ERROR("invalid IPv6 address format: {}",ipv6);
        return ipv6; // Or throw a more specific error/log message
    }
}

inline bool isValidIPv4Address(in_addr* addr, Type type)
{
    uint8_t ip[4];
    in_addr_t tmp = stdplus::ntoh(addr->s_addr);
    for (int i = 0; i < 4; i++)
    {
        ip[i] = ( tmp >> (8 * (3 - i)) ) & 0xFF;
    }
    if (type == Type::GATEWAY4_ADDRESS)
    {
        if (ip[0] == 0)
        {
            // Gateway starts with 0
            return false;
        }
    }
    else if (type == Type::IP4_ADDRESS || type == Type::SUBNETMASK)
    {
        if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0)
        {
            // IPv4 address is 0.0.0.0
            return false;
        }
    }
    return true;
}

inline std::string extractIPv4FromMappedIPv6(const boost::asio::ip::address& addr)
{
    if (addr.is_v4())
    {
        return addr.to_string();  // Already an IPv4 address
    }
    else if (addr.is_v6()) 
    {
        const auto& ipv6 = addr.to_v6();
        if (ipv6.is_v4_mapped()) // ::ffff:XX.X.XX.XXX
        {
            auto bytes = ipv6.to_bytes();  // 16 bytes
            std::ostringstream oss;
            oss << static_cast<int>(bytes[12]) << "."
                << static_cast<int>(bytes[13]) << "."
                << static_cast<int>(bytes[14]) << "."
                << static_cast<int>(bytes[15]);
            return oss.str();  // XX.X.XX.XXX
        }
        else
        {
            return addr.to_string();  // Regular IPv6
        }
    }
    return {};
}

inline bool isValidIPv4Addr(std::string addr, Type type)
{
    try
    {
        std::optional<stdplus::InAnyAddr> Addrs;
        Addrs.emplace(stdplus::fromStr<stdplus::In4Addr>(addr));
        bool ValidIPv4Addrflag = isValidIPv4Address(reinterpret_cast<in_addr*> ((&Addrs.value())), type);
        return ValidIPv4Addrflag;
    }
    catch (const std::exception& e)
    {
        syslog(LOG_WARNING, "isValidIPv4Addr IP : %s is Invalid & Error Returned is : %s !!! \n", addr.c_str(), e.what());
        return false;
    }
}

} // namespace ip_util
} // namespace redfish
