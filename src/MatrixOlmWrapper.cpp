#include "MatrixOlmWrapper.hpp"

#include <chrono>
#include <memory>
#include <stdlib.h>
#include <string>
#include <thread>

#include "utils.hpp"

using namespace OlmWrapper::utils;

////////////////////////////////////////////////////////////
//                   Member Functions                     //
////////////////////////////////////////////////////////////
void MatrixOlmWrapper::setupIdentityKeys() {
    if (!id_published) {
        if (identity_keys.empty()) {
            int id_buff_size = acct->get_identity_json_length();
            unique_ptr<uint8_t[]> id_buff(new uint8_t[id_buff_size]);
            if (size_t(-1) != acct->get_identity_json(id_buff.get(), id_buff_size)) {
                identity_keys = string(reinterpret_cast<const char*>(id_buff.get()));
            } else {
                // Couldnt get the identity keys
                return;
            }
        }

        // Form json and publish keys
        if (!identity_keys.empty()) {
            try {
                json id       = json::parse(identity_keys);
                json key_data = {
                    {"algorithms", {"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"}},
                    {"keys",
                     {{"curve25519:" + device_id, id["curve25519"]},
                      {"ed25519:" + device_id, id["ed25519"]}}},
                    {"device_id:", device_id},
                    {"user_id", user_id}};

                // Sign keyData
                string sig                                              = signData(key_data, acct);
                key_data["signatures"][user_id]["ed25519:" + device_id] = sig;

                // Upload keys
                string key_string                       = key_data.dump();
                APIWrapper::matrAPIRet individKeyUpload = wrapper->uploadKeys(key_string);
                auto err                                = get<1>(individKeyUpload);
                if (!err) {
                    id_published = true;
                    // Add our keys to our list of verified devices
                    verified[user_id][device_id] = id["ed25519"].get<string>();
                }
            } catch (const exception& e) {
                cout << "Encountered an issue during identity key setup: " << endl
                     << e.what() << endl;
                return;
            }
        }
    }
}

/*
 * key should contain one key formatted as follows {"<key_id>":
 * "<curve25519_key>"}
 * Upon error, nullptr is returned
 */
json MatrixOlmWrapper::signKey(json& key) {
    json to_sign, signed_key;
    try {
        to_sign["key"]   = key.begin().value();
        string signature = signData(to_sign, acct);
        if (!signature.empty()) {
            signed_key = {{"signed_curve25519:" + key.begin().key(),
                           {{to_sign.begin().key(), to_sign.begin().value()},
                            {"signatures", {{user_id, {{"ed25519:" + device_id, signature}}}}}}}};
            return signed_key;
        } else {
            // Couldnt sign properly, return nullptr to signify this
            return nullptr;
        }
    } catch (const exception& e) {
        cout << "Encountered an issue during key signing: " << endl << e.what() << endl;
        return nullptr;
    }
}

/*
 * Returns the number of keys which were generated and signed
 * Upon successful return, data will contain the signed keys and num_keys will
 * be returned Upon error, data will be restored to its original state, and 0
 * will be returned
 */
int MatrixOlmWrapper::genSignedKeys(json& data, int num_keys) {
    int rand_length                 = acct->generate_one_time_keys_random_length(num_keys);
    unique_ptr<uint8_t[]> rand_data = getRandData(rand_length);
    json original_data              = data;
    try {
        if (size_t(-1) != acct->generate_one_time_keys(num_keys, rand_data.get(), rand_length)) {
            int keys_size = acct->get_one_time_keys_json_length();
            unique_ptr<uint8_t[]> keys(new uint8_t[keys_size]);
            if (size_t(-1) != acct->get_one_time_keys_json(keys.get(), keys_size)) {
                json one_time_keys = json::parse(string(reinterpret_cast<const char*>(keys.get())));
                json signed_key;

                for (auto it = one_time_keys["curve25519"].begin();
                     it != one_time_keys["curve25519"].end(); ++it) {
                    json key;
                    key[it.key()] = it.value();
                    if ((signed_key = signKey(key)) == nullptr) {
                        data = original_data;
                        return 0;
                    }
                    data["one_time_keys"][signed_key.begin().key()] = signed_key.begin().value();
                }

                return num_keys;
            } else {
                // Couldnt retrieve one time keys
                data = original_data;
                return 0;
            }
        } else {
            // Couldnt generate one time keys
            data = original_data;
            return 0;
        }
    } catch (const exception& e) {
        cout << "Encountered an issue during signed key generation: " << endl << e.what() << endl;
        data = original_data;
        return 0;
    }
}

// TODO add synchronization
void MatrixOlmWrapper::replenishKeyJob() {
    try {
        // Call upload keys to figure out how many keys are present
        string empty                    = "{}";
        APIWrapper::matrAPIRet keyCount = wrapper->uploadKeys(empty);
        string key_counts               = get<0>(keyCount);
        int current_key_count           = 0;
        if (!key_counts.empty() && json::parse(key_counts).count("one_time_key_counts") == 1) {
            current_key_count =
                json::parse(key_counts)["one_time_key_counts"]["signed_curve25519"].get<int>();
        }

        int keys_needed = static_cast<int>(acct->max_number_of_one_time_keys()) - current_key_count;

        if (keys_needed) {
            json data;
            if (genSignedKeys(data, keys_needed) > 0) {
                // Simple test below to show how verify works
                json check_sig(data["one_time_keys"].begin().value());

                string data_string                   = data.dump(2);
                APIWrapper::matrAPIRet massKeyUpload = wrapper->uploadKeys(data_string);
                string resp                          = get<0>(massKeyUpload);
                auto err                             = get<1>(massKeyUpload);
                if (!err) {
                    if (json::parse(resp)["one_time_key_counts"]["signed_curve25519"].get<int>() >
                        current_key_count) {
                        acct->mark_keys_as_published();
                    }
                }
            }
        }
    } catch (const exception& e) {
        cout << "Encountered an issue during key replenishment: " << endl << e.what() << endl;
        return;
    }
}

shared_ptr<olm::Account> MatrixOlmWrapper::loadAccount(string keyfile_path, string keyfile_pass) {
    shared_ptr<olm::Account> acct(new olm::Account);
    if (keyfile_path == "" && keyfile_pass == "") {
        int random_size              = acct->new_account_random_length();
        unique_ptr<uint8_t[]> random = getRandData(random_size);
        if (size_t(-1) != acct->new_account(random.get(), random_size)) {
            thread([this]() {
                while (true) {
                    setupIdentityKeys();
                    if (id_published) {
                        replenishKeyJob();
                    }
                    this_thread::sleep_for(chrono::minutes(10));
                    // this_thread::sleep_for(chrono::seconds(1));
                }
            })
                .detach();

            return acct;
        } else {
            // Error occurred, throw exception
            return nullptr;
        }
    } else {
        // Stubbed functionality
        return nullptr;
    }
}