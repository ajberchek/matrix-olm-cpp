#include "MatrixOlmWrapper.hpp"

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>

#include "olm/base64.hh"
#include "olm/utility.hh"

#include <sodium.h>
#include <stdlib.h>

////////////////////////////////////////////////////////////
//                    Helper Functions                    //
////////////////////////////////////////////////////////////
// buffer_size is the size of the buffer in number of bytes
unique_ptr<uint8_t[]> getRandData(unsigned int buffer_size) {
    unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_size]);
    randombytes_buf(buffer.get(), buffer_size);
    return buffer;
}

// returns (success_status, user_id, device_id, ed25519_key) if found
tuple<bool, string, string, string> getMsgInfo(json& m) {
    tuple<bool, string, string, string> unsuccessful;
    try {
        string user     = m["signatures"].begin().key();
        string algo_dev = m["signatures"].begin().value().begin().key();
        if (algo_dev.find(':') == string::npos) {
            return unsuccessful;
        }

        string dev = algo_dev.substr(algo_dev.find(':') + 1, algo_dev.size());
        string sentKey;
        if (m.count("keys") > 0) {
            string sentKey = m["keys"]["ed25519:" + dev];
        }
        return {true, user, dev, sentKey};
    } catch (exception& e) {
        cout << "Encountered an issue during Message Sender Info Retrieval: " << endl
             << e.what() << endl;
        return unsuccessful;
    }
}
bool getMsgUsrId(json& m, string& usr) {
    auto info = getMsgInfo(m);
    if (get<0>(info)) {
        usr = get<1>(info);
        return true;
    } else {
        return false;
    }
}
bool getMsgDevId(json& m, string& dev) {
    auto info = getMsgInfo(m);
    if (get<0>(info)) {
        dev = get<2>(info);
        return true;
    } else {
        return false;
    }
}
bool getMsgKey(json& m, string& key) {
    auto info = getMsgInfo(m);
    if (get<0>(info)) {
        key = get<3>(info);
        return true;
    } else {
        return false;
    }
}

// Encodes the json object to a properly formatted string (According to
// https://matrix.org/speculator/spec/HEAD/appendices.html#signing-json)
void toSignable(json data, string& encoded) {
    // Remove data which shouldnt be signed
    data.erase("signatures");
    data.erase("unsigned");

    // Keys encoded in alphabetical order with no whitespace
    encoded = data.dump();
}

// Generate a base64 encoded signature
string signData(const string& message, shared_ptr<olm::Account> acct) {
    int m_len        = message.size();
    const uint8_t* m = reinterpret_cast<const uint8_t*>(message.c_str());
    int sig_len      = acct->signature_length();

    unique_ptr<uint8_t[]> sig(new uint8_t[sig_len]);
    unique_ptr<uint8_t[]> sig_base64(new uint8_t[olm::encode_base64_length(sig_len)]);

    if (size_t(-1) != acct->sign(m, m_len, sig.get(), sig_len)) {
        olm::encode_base64(sig.get(), sig_len, sig_base64.get());
        return string(reinterpret_cast<const char*>(sig_base64.get()));
    }
    return string();
}
string signData(const json& message, shared_ptr<olm::Account> acct) {
    string m;
    toSignable(message, m);
    return signData(m, acct);
}

// Verify a signature
bool verify(string& message, string& sig, _olm_ed25519_public_key& key) {
    const uint8_t* m = reinterpret_cast<const uint8_t*>(message.c_str());
    int sig_dec_len  = olm::decode_base64_length(sig.size());
    const uint8_t* s = reinterpret_cast<const uint8_t*>(sig.c_str());
    unique_ptr<uint8_t[]> sig_dec(new uint8_t[sig_dec_len]);
    olm::decode_base64(s, sig.size(), sig_dec.get());

    return size_t(0) ==
           olm::Utility().ed25519_verify(key, m, message.size(), sig_dec.get(), sig_dec_len);
}
bool verify(string& message, string& sig, string& key) {
    // Decode key to char array
    int key_dec_len = olm::decode_base64_length(key.size());
    if (key_dec_len == ED25519_PUBLIC_KEY_LENGTH) {
        struct _olm_ed25519_public_key pub_key;
        const uint8_t* k = reinterpret_cast<const uint8_t*>(key.c_str());
        olm::decode_base64(k, key.size(), pub_key.public_key);
        return verify(message, sig, pub_key);
    }
    return false;
}
bool verify(json& message, string& key) {
    // sig = signatures.user_id.key
    string sig = message["signatures"].begin().value().begin().value();
    string m_formatted;
    toSignable(message, m_formatted);
    return verify(m_formatted, sig, key);
}
bool verify(json& message, MatrixOlmWrapper* wrap) {
    try {
        string usr, dev;
        if (!getMsgUsrId(message, usr) || !getMsgDevId(message, dev)) {
            return false;
        }

        // A valid public key should never be ""
        string key = wrap->getUserDeviceKey(usr, dev);
        // TODO check for empty key
        if (key.empty()) {
            string sentKey;
            if (getMsgKey(message, sentKey) && wrap->promptVerifyDevice != nullptr &&
                wrap->promptVerifyDevice(usr, dev, sentKey)) {
                wrap->verifyDevice(usr, dev, sentKey);
                return verify(message, sentKey);
            } else {
                return false;
            }
        } else {
            return verify(message, key);
        }
    } catch (exception& e) {
        cout << "Encountered an issue during verification: " << endl << e.what() << endl;
        return false;
    }
}

////////////////////////////////////////////////////////////
//                   Member Functions                     //
////////////////////////////////////////////////////////////
void MatrixOlmWrapper::setupIdentityKeys() {
    if (!id_published) {
        if (identity_keys_.empty()) {
            int id_buff_size = acct->get_identity_json_length();
            unique_ptr<uint8_t[]> id_buff(new uint8_t[id_buff_size]);
            if (size_t(-1) != acct->get_identity_json(id_buff.get(), id_buff_size)) {
                identity_keys_ = string(reinterpret_cast<const char*>(id_buff.get()));
            } else {
                // Couldnt get the identity keys
                return;
            }
        }

        // Form json and publish keys
        if (!identity_keys_.empty() && uploadKeys != nullptr) {
            try {
                json id       = json::parse(identity_keys_);
                json key_data = {
                    {"algorithms", {"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"}},
                    {"keys",
                     {{"curve25519:" + device_id_, id["curve25519"]},
                      {"ed25519:" + device_id_, id["ed25519"]}}},
                    {"device_id:", device_id_},
                    {"user_id", user_id_}};

                // Sign keyData
                string sig = signData(key_data, acct);
                key_data["signatures"][user_id_]["ed25519:" + device_id_] = sig;

                // Upload keys
                string key_string           = key_data.dump();
                matrAPIRet individKeyUpload = uploadKeys(key_string).get();
                auto err                    = get<1>(individKeyUpload);
                if (!err) {
                    id_published = true;
                    // Add our keys to our list of verified devices
                    verified[user_id_][device_id_] = id["ed25519"].get<string>();
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
                            {"signatures", {{user_id_, {{"ed25519:" + device_id_, signature}}}}}}}};
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
        string empty          = "{}";
        matrAPIRet keyCount   = uploadKeys(empty).get();
        string key_counts     = get<0>(keyCount);
        int current_key_count = 0;
        if (!key_counts.empty() && json::parse(key_counts).count("one_time_key_counts") == 1) {
            current_key_count =
                json::parse(key_counts)["one_time_key_counts"]["signed_curve25519"].get<int>();
        }

        int keys_needed = static_cast<int>(acct->max_number_of_one_time_keys()) - current_key_count;

        if (keys_needed) {
            json data;
            if (genSignedKeys(data, keys_needed) > 0 && uploadKeys != nullptr) {
                // Simple test below to show how verify works
                json check_sig(data["one_time_keys"].begin().value());

                string data_string       = data.dump(2);
                matrAPIRet massKeyUpload = uploadKeys(data_string).get();
                string resp              = get<0>(massKeyUpload);
                auto err                 = get<1>(massKeyUpload);
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