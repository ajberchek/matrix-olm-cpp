#ifndef UTILS
#define UTILS
#include <functional>
#include <iostream>
#include <memory>
#include <tuple>
#include <fstream>
#include <string>
#include <cerrno>

#include <sodium.h>
#include <json.hpp>
#include <olm/olm.h>

#include "MatrixOlmWrapper.hpp"

using json = nlohmann::json;
using namespace std;

namespace OlmWrapper{
namespace utils {
/*
* Below deleter functionality reused from mujx/mtxclient
* 
Copyright (c) 2018 Konstantinos Sideris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
*
*/
struct OlmDeleter
{
    void operator()(OlmAccount *ptr) { operator delete(ptr, olm_account_size()); }
    void operator()(OlmUtility *ptr) { operator delete(ptr, olm_utility_size()); }

    void operator()(OlmSession *ptr) { operator delete(ptr, olm_session_size()); }
    void operator()(OlmOutboundGroupSession *ptr)
    {
            operator delete(ptr, olm_outbound_group_session_size());
    }
    void operator()(OlmInboundGroupSession *ptr)
    {
            operator delete(ptr, olm_inbound_group_session_size());
    }
};

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
string signData(const string& message, shared_ptr<OlmAccount> acct) {
    int sig_len      = olm_account_signature_length(acct.get());
    unique_ptr<uint8_t[]> sig(new uint8_t[sig_len]);
    if (olm_error() != olm_account_sign(acct.get(), message.data(), message.size(), sig.get(), sig_len)) {
        return string(reinterpret_cast<const char*>(sig.get()));
    }
    return string();
}
string signData(const json& message, shared_ptr<OlmAccount> acct) {
    string m;
    toSignable(message, m);
    return signData(m, acct);
}

// Verify a signature
bool verify(string& message, string& sig, string& key) {
    //TODO Create a utility
    unique_ptr<OlmUtility, OlmDeleter> util(olm_utility(new uint8_t[olm_utility_size()]));
    return olm_error() != olm_ed25519_verify(util.get(), key.data(), key.size(), message.data(), message.size(), sig.data(), sig.size());
}
bool verify(json& message, string& key) {
    // sig = signatures.user_id.key
    string sig = message["signatures"].begin().value().begin().value();
    string m_formatted;
    toSignable(message, m_formatted);
    return verify(m_formatted, sig, key);
}

}
}
#endif