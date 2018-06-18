#ifndef UTILS
#define UTILS
#include <functional>
#include <iostream>
#include <memory>
#include <tuple>
#include <fstream>
#include <string>
#include <cerrno>

#include <olm/base64.hh>
#include <olm/utility.hh>
#include <olm/account.hh>
#include <olm/session.hh>
#include <sodium.h>
#include <json.hpp>

#include "MatrixOlmWrapper.hpp"

using json = nlohmann::json;
using namespace std;

namespace OlmWrapper{
namespace utils {

////////////////////////////////////////////////////////////
//                    Helper Functions                    //
////////////////////////////////////////////////////////////

// Read the contents of a file to a string
// Taken from: insanecoding.blogspot.com/2011/11/how-to-read-in-file-in-c.html
std::string getFileContents(const char *filename)
{
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (in)
  {
    std::string contents;
    in.seekg(0, std::ios::end);
    contents.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read(&contents[0], contents.size());
    in.close();
    return(contents);
  }
  throw(errno);
}

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
            sentKey = m["keys"]["ed25519:" + dev];
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
            if (getMsgKey(message, sentKey) && wrap->wrapper->promptVerifyDevice(usr, dev, sentKey)) {
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

}
}
#endif