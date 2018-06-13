#pragma once

#include "APIWrapper.hpp"

class APIWrapperTestImpl : public APIWrapper {
    public:
        virtual matrAPIRet uploadKeys(std::string& key_upload) {
            /*
            std::cout << "Upload Keys is uploading: " << std::endl
                    << nlohmann::json::parse(key_upload).dump(2) << std::endl;
            */
            int total_uploaded = 0;
            nlohmann::json dat = nlohmann::json::parse(key_upload)["one_time_keys"];

            for (auto it = dat.begin(); it != dat.end(); ++it) {
                if (it.key().find(":") != std::string::npos) {
                    ++key_counts[it.key().substr(0, it.key().find(":"))];
                    ++total_uploaded;
                }
            }

            nlohmann::json response;
            for (auto& elem : key_counts) {
                response["one_time_key_counts"][elem.first] = elem.second;
            }

            //std::cout << "Client just uploaded " << total_uploaded << " keys" << std::endl;

            return {response.dump(), std::experimental::optional<std::string>()};
        }

        virtual bool promptVerifyDevice(std::string& usr, std::string& dev, std::string& key) {
            std::string verified;
            while (verified != "Y" && verified != "N") {
                std::cout << "Do you trust \"" << usr << "\"\'s device, \"" << dev << "\", with key: \""
                        << key << "\"?(Y/N): ";
                std::cin >> verified;
                std::cout << endl;
            }
            return verified == "Y";
        }

        virtual matrAPIRet queryKeys(string&) { return {"", std::experimental::optional<std::string>()}; }
        virtual matrAPIRet claimKeys(string&) { return {"", std::experimental::optional<std::string>()}; }
        virtual matrAPIRet mgetKeyChanges(string&, string&) { return {"", std::experimental::optional<std::string>()}; }

        virtual ~APIWrapperTestImpl() {}

    public:
        std::unordered_map<std::string, int> key_counts;
};