#pragma once

#include <experimental/optional>
#include <functional>
#include <memory>

#include "olm/olm.h"

class olmWrapper {
public:
  // Public Functions

  // An empty keyfile_path and keyfile_pass indicates keys shouldn't be
  // persisted
  olmWrapper(std::string device_id, std::string user_id)
      : olmWrapper(device_id, user_id, "", "") {}

  olmWrapper(std::string device_id, std::string user_id,
             std::string keyfile_path, std::string keyfile_pass) {
    device_id_ = device_id;
    user_id_ = user_id;
    acct = loadAccount(keyfile_path, keyfile_pass);
  }

  // Client should be able to use acct information, but we may want to restrict
  // writing to our copy in the future
  OlmAccount *getAccount() { return acct; }

public:
  // Public Variables

  // The below functions need to be provided by the client in the described
  // format before any homeserver interactions can take place Client provided
  // functions should take in strings of the json objects related to the
  // endpoint they are contacting unless otherwise specified

  using keyRequestErr = std::experimental::optional<std::string>;
  // Uploads device keys to /_matrix/client/r0/keys/upload
  std::function<void(
      std::string &key_upload,
      std::function<void(const std::string &upload_response, keyRequestErr)>)>
      uploadKeys;
  // Returns current device and id keys for the given user from
  // /_matrix/client/r0/keys/query user_id is the user_id who's keys we are
  // requesting
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
  // Indicates whether or not, data is being persisted to disk
  bool persisting;
};
