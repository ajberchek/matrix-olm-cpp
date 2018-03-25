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
  std::string response = "{\"one_time_key_counts\": {\"curve25519\": "
                         "10,\"signed_curve25519\": 20}}";

  callback(response, std::experimental::optional<std::string>());
}

int main() {
  // Simple sanity check to verify function linking works
  MatrixOlmWrapper m("", "");
  m.uploadKeys = uploadKeys;
  std::cout << "Identity Keys " << m.identity_keys_ << std::endl;

  std::string arg = "{}";
  m.uploadKeys(arg, [](const std::string &res,
                       std::experimental::optional<std::string>) {
    std::cout << "Result of upload keys: " << std::endl << res << std::endl;
  });
}