#pragma once

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace module_command
{
    // Commands
    const std::string SET_GROUP_COMMAND = "set-group";
    const std::string FETCH_CONFIG_COMMAND = "fetch-config";
    const std::string RESTART_COMMAND = "restart";

    // Commands arguments
    const std::string GROUPS_ARG = "groups";

    /// @brief Maximum length of a group name, matching the manager's MAX_GROUP_NAME
    constexpr std::size_t MAX_GROUP_ID_LENGTH = 255;

    /// @brief Checks whether a group name is safe to use in file paths and download URLs
    /// @details Mirrors the manager API rule: letters, digits, '.', '_' and '-', excluding "." and "..".
    /// @param groupId The group name to check
    /// @return True if the group name is valid, false otherwise
    inline bool IsValidGroupId(std::string_view groupId)
    {
        if (groupId.empty() || groupId.size() > MAX_GROUP_ID_LENGTH || groupId == "." || groupId == "..")
        {
            return false;
        }

        return std::ranges::all_of(groupId,
                                   [](const char character)
                                   {
                                       return (character >= 'a' && character <= 'z') ||
                                              (character >= 'A' && character <= 'Z') ||
                                              (character >= '0' && character <= '9') || character == '.' ||
                                              character == '_' || character == '-';
                                   });
    }

    /// @brief Formats an untrusted group name for logging: truncated, quoted, with control characters escaped
    /// @param groupId The group name to format
    /// @return The formatted group name
    inline std::string FormatGroupIdForLog(std::string_view groupId)
    {
        return nlohmann::json(std::string(groupId.substr(0, MAX_GROUP_ID_LENGTH)))
            .dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }

    // Modules
    const std::string CENTRALIZED_CONFIGURATION_MODULE = "CentralizedConfiguration";
    const std::string RESTART_HANDLER_MODULE = "RestartHandler";

    /// @brief Status of a command execution
    enum class Status
    {
        SUCCESS,
        FAILURE,
        IN_PROGRESS,
        TIMEOUT,
        UNKNOWN
    };

    /// @brief Execution mode of a command
    enum class CommandExecutionMode
    {
        SYNC,
        ASYNC
    };

    /// @brief Result of a command execution
    struct CommandExecutionResult
    {
        Status ErrorCode = Status::UNKNOWN;
        std::string Message;

        /// @brief Construct a CommandExecutionResult object
        /// @param code The status of the command execution
        /// @param message A message associated with the command execution result
        explicit CommandExecutionResult(Status code = Status::UNKNOWN, std::string message = "")
            : ErrorCode(code)
            , Message(std::move(message))
        {
        }
    };

    /// @brief Data structure to hold the command execution entry
    class CommandEntry
    {
    public:
        /// @brief Construct a CommandEntry object
        CommandEntry()
            : Time(0.0)
            , ExecutionResult(Status::UNKNOWN, "")
        {
        }

        /// @brief Construct a CommandEntry object
        /// @param id The identifier of the command entry
        /// @param module The module of the command
        /// @param command The command to be executed
        /// @param parameters The parameters for the command
        /// @param executionMode The execution mode of the command
        /// @param result The result of the command execution
        /// @param status The status of the command execution
        CommandEntry(std::string id,
                     std::string module,
                     std::string command,
                     nlohmann::json parameters,
                     CommandExecutionMode executionMode,
                     std::string result,
                     Status status)
            : Id(std::move(id))
            , Module(std::move(module))
            , Command(std::move(command))
            , Parameters(std::move(parameters))
            , Time(0.0)
            , ExecutionMode(executionMode)
            , ExecutionResult(status, std::move(result))
        {
        }

        /// @brief Unique identifier of the command entry
        std::string Id;

        /// @brief Module the command belongs to
        std::string Module;

        /// @brief Command to be executed
        std::string Command;

        /// @brief Parameters for the command
        nlohmann::json Parameters;

        /// @brief Time of the command execution
        double Time;

        /// @brief Execution mode (sync or async) of the command.
        CommandExecutionMode ExecutionMode;

        /// @brief Result of the command execution
        CommandExecutionResult ExecutionResult;
    };
} // namespace module_command
