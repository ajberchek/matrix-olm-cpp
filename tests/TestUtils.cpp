#include <json.hpp>
#include <memory>
#include <gtest/gtest.h>

#include "utils.hpp"

using namespace OlmWrapper::utils;

const char* FortyTwo = "tests/data/FortyTwo.txt";
const char* ValidKeyUpload = "tests/data/ValidKeyUpload.json";

TEST(TestUtils, GetFileContents) {
    ASSERT_EQ("42", getFileContents(FortyTwo));
}

TEST(TestUtils, GetRandData) {
    int buff_size = 42;
    ASSERT_FALSE(getRandData(buff_size) == nullptr);
}

TEST(TestUtils, GetMsgInfoInvalid) {
    auto empty = json::parse("{}");
    auto info = getMsgInfo(empty);
    ASSERT_FALSE(get<0>(info));
}
TEST(TestUtils, GetMsgInfoValid) {
    auto device_keys = json::parse(getFileContents(ValidKeyUpload))["device_keys"];
    auto info = getMsgInfo(device_keys);
    ASSERT_TRUE(get<0>(info));
    ASSERT_EQ("@alice:example.com", get<1>(info));
    ASSERT_EQ("JLAFKJWSCS", get<2>(info));
    ASSERT_EQ("lEuiRJBit0IG6nUf5pUzWTUEsRVVe/HJkoKuEww9ULI", get<3>(info));
}
TEST(TestUtils, GetMsgUsrID) {
    auto device_keys = json::parse(getFileContents(ValidKeyUpload))["device_keys"];
    string user_id;
    ASSERT_TRUE(getMsgUsrId(device_keys, user_id));
    ASSERT_EQ("@alice:example.com", user_id);
}
TEST(TestUtils, GetMsgDevID) {
    auto device_keys = json::parse(getFileContents(ValidKeyUpload))["device_keys"];
    string dev_id;
    ASSERT_TRUE(getMsgDevId(device_keys, dev_id));
    ASSERT_EQ("JLAFKJWSCS", dev_id);
}
TEST(TestUtils, GetMsgKey) {
    auto device_keys = json::parse(getFileContents(ValidKeyUpload))["device_keys"];
    string key;
    ASSERT_TRUE(getMsgKey(device_keys, key));
    ASSERT_EQ("lEuiRJBit0IG6nUf5pUzWTUEsRVVe/HJkoKuEww9ULI", key);
}

int main(int argc, char **argv) {
    cout << "---RUNNING UTILITY UNIT TESTS---" << endl;
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
