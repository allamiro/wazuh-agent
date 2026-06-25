#include "logcollector_mock.hpp"

#include <configuration_parser.hpp>
#include <gtest/gtest.h>

#include <memory>
#include <string>

using namespace configuration;
using namespace logcollector;

namespace
{
    /// @brief Runs SetupUnixSocketReaders against the given YAML and returns how many readers were created
    int CountUnixSocketReaders(const std::string& yaml)
    {
        auto logcollector = LogcollectorMock();
        auto config = std::make_shared<ConfigurationParser>(yaml);

        int readerCount = 0;
        EXPECT_CALL(logcollector, AddReader(::testing::_))
            .WillRepeatedly(::testing::Invoke([&readerCount](std::shared_ptr<IReader>) { ++readerCount; }));

        logcollector.SetupUnixSocketReaders(config);
        return readerCount;
    }
} // namespace

TEST(UnixSocketConfig, NoSectionCreatesNoListeners)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      localfiles:
        - /var/log/auth.log
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 0);
}

TEST(UnixSocketConfig, StreamListenerParses)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - type: unix_stream
          path: /var/run/wazuh-syslog.sock
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 1);
}

TEST(UnixSocketConfig, DatagramListenerParses)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - type: unix_dgram
          path: /var/run/wazuh-dgram.sock
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 1);
}

TEST(UnixSocketConfig, MultipleListenersParse)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - type: unix_stream
          path: /var/run/a.sock
        - type: unix_dgram
          path: /var/run/b.sock
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 2);
}

TEST(UnixSocketConfig, UnsupportedTypeIsRejected)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - type: unix_seq
          path: /var/run/a.sock
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 0);
}

TEST(UnixSocketConfig, MissingTypeIsRejected)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - path: /var/run/a.sock
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 0);
}

TEST(UnixSocketConfig, MissingPathIsRejected)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - type: unix_stream
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 0);
}

TEST(UnixSocketConfig, TooLongPathIsRejected)
{
    // 120-character path exceeds the sun_path limit (107).
    const std::string longPath = "/var/run/" + std::string(120, 'a') + ".sock";
    const std::string config = "logcollector:\n  unix_socket:\n    - type: unix_dgram\n      path: " + longPath + "\n";

    EXPECT_EQ(CountUnixSocketReaders(config), 0);
}

TEST(UnixSocketConfig, DuplicatePathIsRejected)
{
    auto constexpr CONFIG_RAW = R"(
    logcollector:
      unix_socket:
        - type: unix_stream
          path: /var/run/a.sock
        - type: unix_dgram
          path: /var/run/a.sock
    )";

    EXPECT_EQ(CountUnixSocketReaders(CONFIG_RAW), 1);
}
