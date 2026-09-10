// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "duplicatable_file_handle.hpp"
#include "logging.hpp"
#include "utility.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <boost/beast/core/buffers_range.hpp>
#include <boost/beast/core/file_posix.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace bmcweb
{
struct HttpBody
{
    // Body concept requires specific naming of classes
    // NOLINTBEGIN(readability-identifier-naming)
    class writer;
    class reader;
    class value_type;
    // NOLINTEND(readability-identifier-naming)

    static std::uint64_t size(const value_type& body);
};

enum class EncodingType
{
    Raw,
    Base64,
};

class HttpBody::value_type
{
    DuplicatableFileHandle fileHandle;
    std::optional<size_t> fileSize;
    std::string strBody;
    bool extensionMagicValidationEnabled = false;
    std::string deferredOpenPath;
    std::string expectedExtension;

    //  Normalize extension case so validation remains case-insensitive.
    std::string normalizeExt(std::string_view ext)
    {
        std::string out(ext);
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) {
                           return static_cast<char>(std::tolower(c));
                       });
        return out;
    }

    // Check if binary data starts with a magic byte sequence.
    bool startsWithMagic(std::string_view data, std::string_view magic) const
    {
        return data.size() >= magic.size() &&
               data.substr(0, magic.size()) == magic;
    }

    // Verify content signature matches claimed extension before writing.
    std::optional<bool> validateByMagic() const
    {
        constexpr std::string_view nrgMagic = "NERO";
        constexpr size_t isoOffset = 0x8001;
        constexpr std::string_view isoMagic = "CD001";
        constexpr size_t isoNeeded = isoOffset + isoMagic.size();

        std::string_view data(strBody);

        if (expectedExtension == ".nrg")
        {
            if (data.size() < nrgMagic.size())
            {
                return std::nullopt;
            }
            return startsWithMagic(data, nrgMagic);
        }

        if (expectedExtension == ".iso")
        {
            if (data.size() < isoNeeded)
            {
                return std::nullopt;
            }
            return std::string_view(data.data() + isoOffset, isoMagic.size()) ==
                   isoMagic;
        }

        if ((expectedExtension == ".img") || (expectedExtension == ".ima"))
        {
            // IMG/IMA should be disk images, not raw MTD or other formats
            // Reject if they have NRG or ISO magic (wrong format)
            if ((data.size()) < (nrgMagic.size()))
            {
                return std::nullopt;
            }
            if (startsWithMagic(data, nrgMagic))
            {
                return false; // NRG format detected, not img/ima
            }

            // Wait until the ISO signature offset is available before trusting
            // MBR-only validation, otherwise isohybrids can slip through.
            if (data.size() < isoNeeded)
            {
                return std::nullopt;
            }
            if (std::string_view(data.data() + isoOffset, isoMagic.size()) ==
                isoMagic)
            {
                return false; // ISO format detected, not img/ima
            }

            // Check for MBR signature at offset 510 (0x55AA for bootable disk)
            // This helps reject raw MTD/flash dumps that lack disk image
            // structure
            constexpr size_t mbrSigOffset = 510;
            constexpr size_t mbrSigSize = 2;
            if (data.size() >= mbrSigOffset + mbrSigSize)
            {
                uint8_t byte0 = static_cast<uint8_t>(data[mbrSigOffset]);
                uint8_t byte1 = static_cast<uint8_t>(data[mbrSigOffset + 1]);

                // MBR signature should be 0x55AA for valid disk images
                if (byte0 == 0x55 && byte1 == 0xAA)
                {
                    return true; // Valid MBR signature found
                }

                // If we have enough data (512 bytes) but no MBR signature,
                // this likely isn't a valid disk image (e.g., MTD dump)
                if (data.size() >= 512)
                {
                    return false; // Not a valid disk image
                }
            }

            // Not enough data yet to verify MBR signature
            return std::nullopt;
        }

        return false;
    }

  public:
    value_type() = default;
    explicit value_type(std::string_view s) : strBody(s) {}
    explicit value_type(EncodingType e) : encodingType(e) {}
    EncodingType encodingType = EncodingType::Raw;

    const boost::beast::file_posix& file() const
    {
        return fileHandle.fileHandle;
    }

    boost::beast::file_posix& file()
    {
        return fileHandle.fileHandle;
    }

    std::string& str()
    {
        return strBody;
    }

    const std::string& str() const
    {
        return strBody;
    }

    std::optional<size_t> payloadSize() const
    {
        if (!fileHandle.fileHandle.is_open())
        {
            return strBody.size();
        }
        if (fileSize)
        {
            if (encodingType == EncodingType::Base64)
            {
                return crow::utility::Base64Encoder::encodedSize(*fileSize);
            }
        }
        return fileSize;
    }

    void clear()
    {
        strBody.clear();
        strBody.shrink_to_fit();
        fileHandle.fileHandle = boost::beast::file_posix();
        fileSize = std::nullopt;
        encodingType = EncodingType::Raw;
        extensionMagicValidationEnabled = false;
        deferredOpenPath.clear();
        expectedExtension.clear();
    }

    // Store deferred target path and extension for magic validation.
    void configureExtensionMagicValidation(const std::string& path,
                                           std::string_view extension)
    {
        extensionMagicValidationEnabled = true;
        deferredOpenPath = path;
        expectedExtension = normalizeExt(extension);
        strBody.clear();
    }

    // Open file only after validation succeeds, then flush buffered data.
    bool validateAndOpen(boost::system::error_code& ec)
    {
        ec = {};

        if (!extensionMagicValidationEnabled || fileHandle.fileHandle.is_open())
        {
            ec = {};
            return true;
        }

        auto clearDeferredValidationState = [this]() {
            extensionMagicValidationEnabled = false;
            deferredOpenPath.clear();
            expectedExtension.clear();
            strBody.clear();
            strBody.shrink_to_fit();
        };

        try
        {
            std::optional<bool> state = validateByMagic();
            if (!state.has_value())
            {
                // Not enough bytes buffered yet to make a signature decision.
                return true;
            }

            if (!*state)
            {
                BMCWEB_LOG_WARNING("Binary extension check failed");
                throw std::invalid_argument(
                    "Binary signature does not match file extension");
            }

            open(deferredOpenPath.c_str(), boost::beast::file_mode::write, ec);
            if (ec)
            {
                throw std::runtime_error("Failed to open deferred upload file");
            }

            if (!strBody.empty())
            {
                fileHandle.fileHandle.write(strBody.data(), strBody.size(), ec);
                if (ec)
                {
                    throw std::runtime_error(
                        "Failed to write buffered upload data");
                }
            }
        }
        catch (const std::invalid_argument& e)
        {
            BMCWEB_LOG_WARNING("{}", e.what());
            clearDeferredValidationState();
            ec = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            return false;
        }
        catch (const std::exception& e)
        {
            BMCWEB_LOG_ERROR("Exception in validateAndOpen: {} (ec={})",
                             e.what(), ec.message());
            clearDeferredValidationState();
            if (!ec)
            {
                ec = boost::system::errc::make_error_code(
                    boost::system::errc::io_error);
            }
            return false;
        }

        clearDeferredValidationState();
        return true;
    }

    // Open file handle and initialize metadata for streaming operations.
    void open(const char* path, boost::beast::file_mode mode,
              boost::system::error_code& ec)
    {
        fileHandle.fileHandle.open(path, mode, ec);
        if (ec)
        {
            return;
        }
        boost::system::error_code ec2;
        uint64_t size = fileHandle.fileHandle.size(ec2);
        if (!ec2)
        {
            BMCWEB_LOG_INFO("File size was {} bytes", size);
            fileSize = static_cast<size_t>(size);
        }
        else
        {
            BMCWEB_LOG_WARNING("Failed to read file size on {}", path);
        }

        int fadvise = posix_fadvise(fileHandle.fileHandle.native_handle(), 0, 0,
                                    POSIX_FADV_SEQUENTIAL);
        if (fadvise != 0)
        {
            BMCWEB_LOG_WARNING("Fasvise returned {} ignoring", fadvise);
        }
        ec = {};
    }

    void setFd(int fd, boost::system::error_code& ec)
    {
        fileHandle.fileHandle.native_handle(fd);

        boost::system::error_code ec2;
        uint64_t size = fileHandle.fileHandle.size(ec2);
        if (!ec2)
        {
            if (size != 0 && size < std::numeric_limits<size_t>::max())
            {
                fileSize = static_cast<size_t>(size);
            }
        }
        ec = {};
    }
};

class HttpBody::writer
{
  public:
    using const_buffers_type = boost::asio::const_buffer;

  private:
    std::string buf;
    crow::utility::Base64Encoder encoder;

    value_type& body;
    size_t sent = 0;
    // 64KB This number is arbitrary, and selected to try to optimize for larger
    // files and fewer loops over per-connection reduction in memory usage.
    // Nginx uses 16-32KB here, so we're in the range of what other webservers
    // do.
    constexpr static size_t readBufSize = 1024UL * 64UL;
    std::array<char, readBufSize> fileReadBuf{};

  public:
    template <bool IsRequest, class Fields>
    writer(boost::beast::http::header<IsRequest, Fields>& /*header*/,
           value_type& bodyIn) : body(bodyIn)
    {}

    static void init(boost::beast::error_code& ec)
    {
        ec = {};
    }

    boost::optional<std::pair<const_buffers_type, bool>> get(
        boost::beast::error_code& ec)
    {
        return getWithMaxSize(ec, std::numeric_limits<size_t>::max());
    }

    boost::optional<std::pair<const_buffers_type, bool>> getWithMaxSize(
        boost::beast::error_code& ec, size_t maxSize)
    {
        std::pair<const_buffers_type, bool> ret;
        if (!body.file().is_open())
        {
            size_t remain = body.str().size() - sent;
            size_t toReturn = std::min(maxSize, remain);
            ret.first = const_buffers_type(&body.str()[sent], toReturn);

            sent += toReturn;
            ret.second = sent < body.str().size();
            BMCWEB_LOG_INFO("Returning {} bytes more={}", ret.first.size(),
                            ret.second);
            return ret;
        }
        size_t readReq = std::min(fileReadBuf.size(), maxSize);
        BMCWEB_LOG_INFO("Reading {}", readReq);
        boost::system::error_code readEc;
        size_t read = body.file().read(fileReadBuf.data(), readReq, readEc);
        if (readEc)
        {
            if (readEc != boost::system::errc::operation_would_block &&
                readEc != boost::system::errc::resource_unavailable_try_again)
            {
                BMCWEB_LOG_CRITICAL("Failed to read from file {}",
                                    readEc.message());
                ec = readEc;
                return boost::none;
            }
        }

        std::string_view chunkView(fileReadBuf.data(), read);
        BMCWEB_LOG_INFO("Read {} bytes from file", read);
        // If the number of bytes read equals the amount requested, we haven't
        // reached EOF yet
        ret.second = read == readReq;
        if (body.encodingType == EncodingType::Base64)
        {
            buf.clear();
            buf.reserve(
                crow::utility::Base64Encoder::encodedSize(chunkView.size()));
            encoder.encode(chunkView, buf);
            if (!ret.second)
            {
                encoder.finalize(buf);
            }
            ret.first = const_buffers_type(buf.data(), buf.size());
        }
        else
        {
            ret.first = const_buffers_type(chunkView.data(), chunkView.size());
        }
        return ret;
    }
};

class HttpBody::reader
{
    value_type& value;
    static constexpr std::uint64_t maxStringAllocSize = 128UL * 1024UL * 1024UL;

  public:
    template <bool IsRequest, class Fields>
    reader(boost::beast::http::header<IsRequest, Fields>& /*headers*/,
           value_type& body) : value(body)
    {}

    void init(const boost::optional<std::uint64_t>& contentLength,
              boost::beast::error_code& ec)
    {
        if (contentLength)
        {
            if (!value.file().is_open())
            {
                if (*contentLength < maxStringAllocSize)
                {
                    value.str().reserve(static_cast<size_t>(*contentLength));
                }
            }
        }
        ec = {};
    }

    template <class ConstBufferSequence>
    std::size_t put(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec)
    {
        size_t extra = boost::beast::buffer_bytes(buffers);

        if (!value.file().is_open())
        {
            // Reserve space upfront to minimize reallocations
            value.str().reserve(value.str().size() + extra);

            for (const auto b : boost::beast::buffers_range_ref(buffers))
            {
                const char* ptr = static_cast<const char*>(b.data());
                value.str() += std::string_view(ptr, b.size());
            }

            value.validateAndOpen(ec);
            if (ec)
            {
                return 0;
            }
            return extra;
        }

        if (value.file().is_open())
        {
            for (const auto b : boost::beast::buffers_range_ref(buffers))
            {
                // Write directly to the eMMC file
                value.file().write(b.data(), b.size(), ec);
                if (ec)
                {
                    BMCWEB_LOG_ERROR("Failed to write to file: {}",
                                     ec.message());
                    return 0;
                }
            }
        }
        ec = {};
        return extra;
    }

    static void finish(boost::system::error_code& ec)
    {
        ec = {};
    }
};

inline std::uint64_t HttpBody::size(const value_type& body)
{
    std::optional<size_t> payloadSize = body.payloadSize();
    return payloadSize.value_or(0U);
}

} // namespace bmcweb
