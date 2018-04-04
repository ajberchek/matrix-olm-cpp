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

  // Adds a user_id+pair<device_id,pub_key> to the list of verified devices
  // to_verify is the canonically formatted user_id being added to the verified
  // list. device_and_key contain a is the canonically formatted device_id and
  // formatted public key corresponding to that user and device ID you would
  // like to verify. This pair is to be added in conjunction with the user_id to
  // the verified list
  void verifyDevice(const string &toVerify,
                    const pair<string, string> device_and_key);

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