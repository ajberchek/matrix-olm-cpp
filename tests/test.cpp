#include <experimental/optional>
#include <functional>
#include <iostream>
#include <memory>

#include "MatrixOlmWrapper.hpp"

// Svubbed function to "Upload Keys" which really just returns back dummy data
// to verify the functionality of MatrixOlmWrapper's key management
void uploadKeys(
    std::string &key_upload,
    std::function<void(const std::string &upload_response,
                       std::experimental::optional<std::string> err)>
        callback) {
  std::cout << "Received request to upload key: " << key_upload << std::endl;
  std::string response = "{\n\t\"one_time_key_counts\": {\n\t\t\"curve25519\": "
                         "10,\n\t\t\"signed_curve25519\": 20\n\t}\n}";

  callback(response, std::experimental::optional<std::string>());
}

int main() {
  // Simple sanity check to verify function linking works
  MatrixOlmWrapper m("", "");
  m.uploadKeys = uploadKeys;
  std::string arg = "test";
  m.uploadKeys(arg, [](const std::string &res,
                       std::experimental::optional<std::string>) {
    std::cout << "Result of upload keys: " << std::endl << res << std::endl;
  });
}
