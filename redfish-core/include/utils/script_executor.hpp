#pragma once

#include <app.hpp>
#include <cstdio>
#include <vector>

namespace redfish::script_executor
{
    inline bool executeScriptAndGetResult(const std::string& service, const std::string& scriptPath, const std::string& arg){
        static const std::vector<std::string> validActions = {"start", "stop", "is-active"};

        if (std::find(validActions.begin(), validActions.end(), arg) == validActions.end()) {
            BMCWEB_LOG_ERROR("Invalid action attempted: {}", arg);
            return false;
        }

        const std::string command = "sh "+ scriptPath + " " + arg;

        FILE *pipe = popen(command.c_str(), "r");
        if (!pipe) {
            BMCWEB_LOG_ERROR("{} Failed to open pipe.", service);
            return false;
        }

        const int bufferSize = 256;
        char buffer[bufferSize];
        std::string result;

        while (fgets(buffer, bufferSize, pipe) != nullptr) {
            result += buffer;
        }

        int returnValue = pclose(pipe);
        int exitCode = WEXITSTATUS(returnValue);
        if(exitCode){
            BMCWEB_LOG_ERROR("{} No such file or directory.", service);
            return false;
        }
        bool status = (stoi(result) == 0) ? false : true;

        return status;
    }
} // namespace redfish::script_executor
