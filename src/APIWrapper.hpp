#pragma once

#include <experimental/optional>
#include <tuple>

using namespace std;

// The below class needs to be implemented by the client in the described
// format before any homeserver interactions can take place. Client provided
// functions should take in strings of the json objects related to the
// endpoint they are contacting unless otherwise specified
class APIWrapper {
    public:
        using keyRequestErr = experimental::optional<string>;
        using matrAPIRet    = tuple<string, keyRequestErr>;

    public:
        // Uploads device keys to /_matrix/client/r0/keys/upload
        // Return: (upload_response, keyRequestErr)
        virtual matrAPIRet uploadKeys(string& key_upload) = 0;
        // Returns current device and id keys for the given user from
        // /_matrix/client/r0/keys/query user_id is the canonical representation of
        // the user_id who's keys we are requesting
        // Return: (key_response, keyRequestErr)
        virtual matrAPIRet queryKeys(string& user_id) = 0;
        // Claims one-time keys for use in pre-key messages via
        // /_matrix/client/r0/keys/claim
        // Return: (claimed_key, keyRequestErr)
        virtual matrAPIRet claimKeys(string& key_claim) = 0;
        // Gets a list of users who updated their device identity keys since a
        // previous sync token by contacting /_matrix/client/r0/keys/changes from is
        // the desired start point of the list to is the desired end point of the list
        // Return: (key_changes, keyRequestErr)
        virtual matrAPIRet getKeyChanges(string& from, string& to) = 0;

        // Function implemented by client that this wrapper should call when it is
        // requested to verify a device that is untrusted.
        // This should prompt the user to verify or deny that they trust the device.
        // Return true if the user decided to verify the device, and false otherwise.
        // If true, then verifyDevice will be called with these parameters as well.
        virtual bool promptVerifyDevice(string& user_id, string& dev_id, string& fingerprint_key) = 0;

        virtual ~APIWrapper() {}
};