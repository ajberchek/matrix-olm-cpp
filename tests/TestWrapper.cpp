#include <experimental/optional>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <json.hpp>
#include <memory>
#include <thread>

#include "APIWrapperTestImpl.hpp"
#include "MatrixOlmWrapper.hpp"

TEST(TestWrapper, UploadsExpectedNumKeys) {
    APIWrapperTestImpl* api = new APIWrapperTestImpl();
    MatrixOlmWrapper m(api, "HeartOfGold", "Zaphod");

    this_thread::sleep_for(chrono::seconds(1));

    int expected_key_count = 100;
    int total_sum          = 0;
    for (auto& elem : api->key_counts) {
        total_sum += elem.second;
    }

    ASSERT_EQ(expected_key_count, total_sum);
}

int main(int argc, char** argv) {
    cout << "---RUNNING WRAPPER TESTS---" << endl;
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
