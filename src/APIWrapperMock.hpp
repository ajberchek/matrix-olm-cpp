#pragma once

#include <gmock/gmock.h>
#include "APIWrapper.hpp"

class APIWrapperMock : public APIWrapper {
    public:
        MOCK_METHOD1(uploadKeys, matrAPIRet(string& key_upload));
        MOCK_METHOD1(queryKeys, matrAPIRet(string& user_id)); 
        MOCK_METHOD1(claimKeys, matrAPIRet(string& key_claim));
        MOCK_METHOD2(getKeyChanges, matrAPIRet(string& from, string& to));
        MOCK_METHOD3(promptVerifyDevice, bool(string& user_id, string& dev_id, string& fingerprint_key));
};