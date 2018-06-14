#include <json.hpp>
#include <memory>
#include <gtest/gtest.h>

#include "utils.hpp"

using namespace OlmWrapper::utils;

TEST(TestUtils, GetRandData) {
    int buff_size = 42;
    ASSERT_FALSE(getRandData(buff_size) == nullptr);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
