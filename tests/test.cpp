#include <experimental/optional>
#include <functional>
#include <iostream>
#include <json.hpp>
#include <memory>

#include "MatrixOlmWrapper.hpp"

std::unordered_map<std::string, int> key_counts;

// Svubbed function to "Upload Keys" which really just returns back dummy data
// to verify the functionality of MatrixOlmWrapper's key management
void uploadKeys(
    std::string &key_upload,
    std::function<void(const std::string &upload_response,
                       std::experimental::optional<std::string> err)>
        callback) {

  std::cout << "Upload Keys is uploading: "
            << nlohmann::json::parse(key_upload).dump(2) << std::endl;

  nlohmann::json dat = nlohmann::json::parse(key_upload)["one_time_keys"];

  for (auto it = dat.begin(); it != dat.end(); ++it) {
    if (it.key().find(":") != std::string::npos) {
      key_counts[it.key().substr(0, it.key().find(":"))]++;
    }
  }

  nlohmann::json response;
  for (auto &elem : key_counts) {
    response["one_time_keys"][elem.first] = elem.second;
  }

  callback(response.dump(), std::experimental::optional<std::string>());
}

int main() {
  // Simple sanity check to verify function linking works
  MatrixOlmWrapper m("", "");
  m.uploadKeys = uploadKeys;

  /*
  std::string arg =
      "{\"device_keys\": {\"user_id\": \"@alice:example.com\",\"device_id\": "
      "\"JLAFKJWSCS\",\"algorithms\": "
      "[\"m.olm.curve25519-aes-sha256\",\"m.megolm.v1.aes-sha\"],\"keys\": "
      "{\"curve25519:JLAFKJWSCS\": "
      "\"3C5BFWi2Y8MaVvjM8M22DBmh24PmgR0nPvJOIArzgyI\",\"ed25519:JLAFKJWSCS\": "
      "\"lEuiRJBit0IG6nUf5pUzWTUEsRVVe/HJkoKuEww9ULI\"},\"signatures\": "
      "{\"@alice:example.com\": {\"ed25519:JLAFKJWSCS\": "
      "\"dSO80A01XiigH3uBiDVx/EjzaoycHcjq9lfQX0uWsqxl2giMIiSPR8a4d291W1ihKJL/"
      "a+myXS367WT6NAIcBA\"}}},\"one_time_keys\": {\"curve25519:AAAAAQ\": "
      "\"/qyvZvwjiTxGdGU0RCguDCLeR+nmsb3FfNG3/"
      "Ve4vU8\",\"signed_curve25519:AAAAHg\": {\"key\": "
      "\"zKbLg+NrIjpnagy+pIY6uPL4ZwEG2v+8F9lmgsnlZzs\",\"signatures\": "
      "{\"@alice:example.com\": {\"ed25519:JLAFKJWSCS\": "
      "\"FLWxXqGbwrb8SM3Y795eB6OA8bwBcoMZFXBqnTn58AYWZSqiD45tlBVcDa2L7RwdKXebW/"
      "VzDlnfVJ+9jok1Bw\"}}},\"signed_curve25519:AAAAHQ\": {\"key\": "
      "\"j3fR3HemM16M7CWhoI4Sk5ZsdmdfQHsKL1xuSft6MSw\",\"signatures\": "
      "{\"@alice:example.com\": {\"ed25519:JLAFKJWSCS\": "
      "\"IQeCEPb9HFk217cU9kw9EOiusC6kMIkoIRnbnfOh5Oc63S1ghgyjShBGpu34blQomoalCy"
      "XWyhaaT3MrLZYQAA\"}}}}}";
  m.uploadKeys(arg, [](const std::string &res,
                       std::experimental::optional<std::string>) {
    std::cout << "Current key count for this device: " << res << std::endl;
  });
  */
  while (true)
    ;
}
