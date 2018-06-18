#ifndef MATRIX_OLM_WRAPPER
#define MATRIX_OLM_WRAPPER

#include <experimental/optional>
#include <functional>
#include <iostream>
#include <memory>
#include <tuple>

#include <json.hpp>
#include <olm/account.hh>
#include <olm/session.hh>

#include "APIWrapper.hpp"

using json = nlohmann::json;
using namespace std;

class MatrixOlmWrapper {
    public:
    // Public Functions

    // An empty keyfile_path and keyfile_pass indicates keys shouldn't be
    // persisted
    MatrixOlmWrapper(APIWrapper* wrapper, string device_id, string user_id)
        : MatrixOlmWrapper(wrapper, device_id, user_id, "", "") {}

    MatrixOlmWrapper(APIWrapper* wrapper_, string device_id_, string user_id_, string keyfile_path,
                     string keyfile_pass) {
        wrapper   = wrapper_;
        device_id = device_id_;
        user_id   = user_id_;
        acct      = loadAccount(keyfile_path, keyfile_pass);
    }

    // The signAndEncrypt, decryptAndVerify, and verifyDevice functions should be
    // called by the client when sending and receiving messages. Provided string
    // data should be the string version of the json object related to the
    // operation described unless otherwise specified.
    using wrapperError = experimental::optional<string>;
    using APIRet       = tuple<string, wrapperError>;

    // Signs and encrypts the message passed in to the specified user, then returns
    // a tuple containing the encrypted data in json format
    APIRet signAndEncrypt(const string& to_user_id, const string& message);

    // Decrypts and verifies the signature of the received message, then returns
    // a tuple containing the plaintext message. Upon a failed signature
    // verification, the message and an error will be passed back to the callback. This way the
    // client can choose what to do with the unverified message
    APIRet decryptAndVerify(const string& secured_message);

    // Adds a user_id-><device_id,pub_key> to the list of verified devices
    void verifyDevice(const string& user_id, const string& device_id, const string& key) {
        verified[user_id][device_id] = key;
    }

    string getUserDeviceKey(const string& user_id, const string& device_id) {
        if (verified.find(user_id) != verified.end() &&
            verified[user_id].find(device_id) != verified[user_id].end()) {
            return verified[user_id][device_id];
        } else {
            return "";
        }
    }

    public:
    // Public Variables

    // Class implementing APIWrapper which provides the necessary client functions to interact with
    // the homeserver
    APIWrapper* wrapper;

    // device_id associated with the client this wrapper is providing
    // functionality to
    string device_id;
    // user_id associated with the client this wrapper is providing functionality
    // to
    string user_id;

    // Identity keys used to identify the device and verify its signatures
    string identity_keys;

    private:
    // Private Functions

    // Loads in an olm account from file, or creates one if no file exists.
    // Empty strings for the keyfile_path and keyfile_pass indicate that no data
    // should be persisted to disk.
    shared_ptr<olm::Account> loadAccount(string keyfile_path, string keyfile_pass);

    json signKey(json& key);
    int genSignedKeys(json& data, int num_keys);
    void setupIdentityKeys();
    void replenishKeyJob();

    private:
    // Private Variables

    // Account used to interact with olm, and store keys.
    shared_ptr<olm::Account> acct;

    // Keeps track of verified devices
    // hashmap(user_id -> hashmap(device_id -> Base64_fingerprint_key))
    unordered_map<string, unordered_map<string, string>> verified;

    // Keeps track of open sessions
    // hashmap(identity_key -> Session)
    unordered_map<string, unique_ptr<olm::Session>> sessions;

    // Indicates whether or not, data is being persisted to disk
    bool persisting;
    // Indicating whether or not identity_keys_ has been published
    bool id_published;
};
#endif