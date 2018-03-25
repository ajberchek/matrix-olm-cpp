#pragma once

#include <experimental/optional>
#include <functional>
#include <iostream>
#include <memory>

#include "olm/olm.h"

class MatrixOlmWrapper {
public:
  // Public Functions

  // An empty keyfile_path and keyfile_pass indicates keys shouldn't be
  // persisted
  MatrixOlmWrapper(std::string device_id, std::string user_id)
      : MatrixOlmWrapper(device_id, user_id, "", "") {}

  MatrixOlmWrapper(std::string device_id, std::string user_id,
                   std::string keyfile_path, std::string keyfile_pass) {
    device_id_ = device_id;
    user_id_ = user_id;
    acct = loadAccount(keyfile_path, keyfile_pass);
  }

  ~MatrixOlmWrapper() {
    if (acct != nullptr) {
      free(acct);
    }
  }

  // The signAndEncrypt, decryptAndVerify, and verifyDevice functions should be
  // called by the client when sending and receiving messages. Provided string
  // data should be the string version of the json object related to the
  // operation described unless otherwise specified. These functions take in
  // function callbacks since they may call asynchronous functions themselves.
  using wrapperError = std::experimental::optional<std::string>;

  // Signs and encrypts the message passed in to the specified user, then passes
  // the encrypted data in json format to the callback function, ready to send
  void signAndEncrypt(
      const std::string &to_user_id, const std::string &message,
      std::function<void(const std::string &secured_message, wrapperError)>);

  // Decrypts and verifies the signature of the received message, then passes
  // the plaintext message to the callback. Upon a failed signature
  // verification, the message and an error will be passed back to the callback.
  // This way the client can choose what to do with the unverified message
  void decryptAndVerify(
      const std::string &secured_message,
      std::function<void(const std::string &message, wrapperError)>);

  // Adds a user_id+pair<device_id,pub_key> to the list of verified devices
  // to_verify is the canonically formatted user_id being added to the verified
  // list. device_and_key contain a is the canonically formatted device_id and
  // formatted public key corresponding to that user and device ID you would
  // like to verify. This pair is to be added in conjunction with the user_id to
  // the verified list
  void verifyDevice(const std::string &toVerify,
                    const std::pair<std::string, std::string> device_and_key);

  // Client should be able to use acct information, but we may want to restrict
  // writing to our copy in the future
  OlmAccount *getAccount() { return acct; }

public:
  // Public Variables

  // The below functions need to be provided by the client in the described
  // format before any homeserver interactions can take place. Client provided
  // functions should take in strings of the json objects related to the
  // endpoint they are contacting unless otherwise specified

  using keyRequestErr = std::experimental::optional<std::string>;
  // Uploads device keys to /_matrix/client/r0/keys/upload
  std::function<void(
      std::string &key_upload,
      std::function<void(const std::string &upload_response, keyRequestErr)>)>
      uploadKeys;
  // Returns current device and id keys for the given user from
  // /_matrix/client/r0/keys/query user_id is the canonical representation of
  // the user_id who's keys we are requesting
  std::function<void(
      std::string &user_id,
      std::function<void(const std::string &key_response, keyRequestErr)>)>
      queryKeys;
  // Claims one-time keys for use in pre-key messages via
  // /_matrix/client/r0/keys/claim
  std::function<void(
      std::string &key_claim,
      std::function<void(const std::string &claimed_key, keyRequestErr)>)>
      claimKeys;
  // Gets a list of users who updated their device identity keys since a
  // previous sync token by contacting /_matrix/client/r0/keys/changes from is
  // the desired start point of the list to is the desired end point of the list
  std::function<void(
      std::string &from, std::string &to,
      std::function<void(const std::string &key_changes, keyRequestErr)>)>
      getKeyChanges;

  // device_id associated with the client this wrapper is providing
  // functionality to
  std::string device_id_;
  // user_id associated with the client this wrapper is providing functionality
  // to
  std::string user_id_;

  // Identity keys used to identify the device and verify its signatures
  std::string identity_keys_;

private:
  // Private Functions

  // Loads in an olm account from file, or creates one if no file exists.
  // Empty strings for the keyfile_path and keyfile_pass indicate that no data
  // should be persisted to disk.
  OlmAccount *loadAccount(std::string keyfile_path, std::string keyfile_pass);

private:
  // Private Variables

  // Account used to interact with olm, and store keys.
  // using a CPtr to combat lack of the required sizeof operator for unique and
  // shared Ptrs
  OlmAccount *acct;

  // Keeps track of verified devices
  // hashmap(user_id -> hashmap(device_id -> Base64_fingerprint_key))
  std::unordered_map<std::string, std::unordered_map<std::string, std::string>>
      verified;

  // Keeps track of open sessions
  // hashmap(identity_key -> Session)
  std::unordered_map<std::string, OlmSession *> sessions;

  // Indicates whether or not, data is being persisted to disk
  bool persisting;
  // Indicating whether or not identity_keys_ has been published
  bool id_published;
};
