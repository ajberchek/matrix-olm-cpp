#include <experimental/optional>
#include <functional>
#include <iostream>
#include <json.hpp>
#include <memory>
#include <thread>
#include <gtest/gtest.h>

#include "MatrixOlmWrapper.hpp"
#include "APIWrapperTestImpl.hpp"

TEST(TestWrapper, UploadsExpectedNumKeys) {
    APIWrapperTestImpl* api = new APIWrapperTestImpl();
    MatrixOlmWrapper m(api, "HeartOfGold", "Zaphod");

    this_thread::sleep_for(chrono::seconds(1));

    int expected_key_count = 100;
    int total_sum = 0;
    for(auto& elem : api->key_counts) {
        total_sum += elem.second;
    }
    
    ASSERT_EQ(expected_key_count, total_sum);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
