#pragma once

#include <experimental/optional>
#include <functional>
#include <iostream>
#include <memory>

#include "olm/account.hh"
#include "olm/session.hh"

#include <json.hpp>
using json = nlohmann::json;

using namespace std;

class MatrixOlmWrapper {
public:
  // Public Functions

  // An empty keyfile_path and keyfile_pass indicates keys shouldn't be
  // persisted
  MatrixOlmWrapper(string device_id, string user_id)
      : MatrixOlmWrapper(device_id, user_id, "", "") {}

  MatrixOlmWrapper(string device_id, string user_id, string keyfile_path,
                   string keyfile_pass) {
    device_id_ = device_id;
    user_id_ = user_id;
    acct = loadAccount(keyfile_path, keyfile_pass);
  }

  // The signAndEncrypt, decryptAndVerify, and verifyDevice functions should be
  // called by the client when sending and receiving messages. Provided string
  // data should be the string version of the json object related to the
  // operation described unless otherwise specified. These functions take in
  // function callbacks since they may call asynchronous functions themselves.
  using wrapperError = experimental::optional<string>;

  // Signs and encrypts the message passed in to the specified user, then passes
  // the encrypted data in json format to the callback function, ready to send
  void
  signAndEncrypt(const string &to_user_id, const string &message,
                 function<void(const string &secured_message, wrapperError)>);

  // Decrypts and verifies the signature of the received message, then passes
  // the plaintext message to the callback. Upon a failed signature
  // verification, the message and an error will be passed back to the callback.
  // This way the client can choose what to do with the unverified message
  void decryptAndVerify(const string &secured_message,
                        function<void(const string &message, wrapperError)>);

  // Adds a user_id-><device_id,pub_key> to the list of verified devices
  void verifyDevice(const string &user_id, const string &device_id,
                    const string &key) {
    verified[user_id][device_id] = key;
  }

  string getUserDeviceKey(const string &user_id, const string &device_id) {
    if(verified.find(user_id) != verified.end() && verified[user_id].find(device_id) != verified[user_id].end()) {
      return verified[user_id][device_id];
    } else {
      return "";
    }
  }

public:
  // Public Variables

  // The below functions need to be provided by the client in the described
  // format before any homeserver interactions can take place. Client provided
  // functions should take in strings of the json objects related to the
  // endpoint they are contacting unless otherwise specified

  using keyRequestErr = experimental::optional<string>;
  // Uploads device keys to /_matrix/client/r0/keys/upload
  function<void(string &key_upload,
                function<void(const string &upload_response, keyRequestErr)>)>
      uploadKeys;
  // Returns current device and id keys for the given user from
  // /_matrix/client/r0/keys/query user_id is the canonical representation of
  // the user_id who's keys we are requesting
  function<void(string &user_id,
                function<void(const string &key_response, keyRequestErr)>)>
      queryKeys;
  // Claims one-time keys for use in pre-key messages via
  // /_matrix/client/r0/keys/claim
  function<void(string &key_claim,
                function<void(const string &claimed_key, keyRequestErr)>)>
      claimKeys;
  // Gets a list of users who updated their device identity keys since a
  // previous sync token by contacting /_matrix/client/r0/keys/changes from is
  // the desired start point of the list to is the desired end point of the list
  function<void(string &from, string &to,
                function<void(const string &key_changes, keyRequestErr)>)>
      getKeyChanges;

  // Function implemented by client that this wrapper should call when it is
  // requested to verify a device that is untrusted.
  // This should prompt the user to verify or deny that they trust the device.
  // Return true if the user decided to verify the device, and false otherwise.
  // If true, then verifyDevice will be called with these parameters as well.
  function<bool(string &user_id, string &dev_id, string &fingerprint_key)>
      promptVerifyDevice;

  // device_id associated with the client this wrapper is providing
  // functionality to
  string device_id_;
  // user_id associated with the client this wrapper is providing functionality
  // to
  string user_id_;

  // Identity keys used to identify the device and verify its signatures
  string identity_keys_;

private:
  // Private Functions

  // Loads in an olm account from file, or creates one if no file exists.
  // Empty strings for the keyfile_path and keyfile_pass indicate that no data
  // should be persisted to disk.
  shared_ptr<olm::Account> loadAccount(string keyfile_path,
                                       string keyfile_pass);

  json signKey(json &key);
  int genSignedKeys(json &data, int num_keys);
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