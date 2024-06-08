#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <stdplus/net/addr/ip.hpp>
#include <stdplus/numeric/endian.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/conv.hpp>

#include <string>

namespace redfish
{
namespace ip_util
{

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

enum class Type
{
    GATEWAY4_ADDRESS,
    GATEWAY6_ADDRESS,
    IP4_ADDRESS,
    IP6_ADDRESS
};

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

inline bool validateIPv6address(const std::string& ipAddress)
{
    try
    {
        in6_addr addr;
        if (inet_pton(AF_INET6, ipAddress.c_str(), &addr) != 1)
        {
            throw std::invalid_argument("Invalid IPv6 address format");
        }
        isValidIPv6Addr(&addr, Type::IP6_ADDRESS);
    }
    catch (const std::invalid_argument& e)
    {
        // Invalid IPv6 address.
        return false;
    }
    return true;
}

} // namespace ip_util
} // namespace redfish
