#include "MatrixOlmWrapper.hpp"

#include <chrono>
#include <memory>
#include <thread>

#include "olm/base64.hh"

#include <sodium.h>
#include <stdlib.h>

/*
 * buffer_size is the size of the buffer in number of bytes
 */
std::unique_ptr<uint8_t[]> getRandData(unsigned int buffer_size) {
  std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_size]);
  randombytes_buf(buffer.get(), buffer_size);
  return buffer;
}

void MatrixOlmWrapper::setupIdentityKeys() {
  if (!id_published) {
    if (identity_keys_.empty()) {
      int id_buff_size = acct->get_identity_json_length();
      std::unique_ptr<uint8_t[]> id_buff(new uint8_t[id_buff_size]);
      if (std::size_t(-1) !=
          acct->get_identity_json(id_buff.get(), id_buff_size)) {
        identity_keys_ =
            std::string(reinterpret_cast<const char *>(id_buff.get()));
      } else {
        // Couldnt get the identity keys
        return;
      }
    }

    // Form json and publish keys
    if (!identity_keys_.empty() && uploadKeys != nullptr) {
      try {
        json id = json::parse(identity_keys_);
        json keyData = {
            {"algorithms",
             {"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"}},
            {"keys",
             {{"curve25519:" + device_id_, id["curve25519"]},
              {"ed25519:" + device_id_, id["ed25519"]}}},
            {"device_id:", device_id_},
            {"user_id", user_id_}};

        std::string keyString = keyData.dump();
        uploadKeys(keyString,
                   [this](const std::string &,
                          std::experimental::optional<std::string> err) {
                     if (!err) {
                       id_published = true;
                     }
                   });
      } catch (const json::exception &e) {
        std::cout << "Encountered an issue during json "
                     "serialization/deserialization: "
                  << std::endl
                  << e.what() << std::endl;
        return;
      } catch (const std::exception &e) {
        std::cout << "Encountered an issue during identity key setup: "
                  << std::endl
                  << e.what() << std::endl;
        return;
      }
    }
  }
}

/*
 * key should contain one key formatted as follows {"<key_id>":
 * "<curve25519_key>"}
 * Upon error, nullptr is returned
 */
json MatrixOlmWrapper::signKey(json &key) {
  int sig_length, message_length;
  const uint8_t *message;
  json to_sign, signed_key;

  try {
    to_sign["key"] = key.begin().value();
    std::string m = to_sign.dump(2);
    message_length = m.size();
    message = reinterpret_cast<const uint8_t *>(m.c_str());
    sig_length = acct->signature_length();
    std::unique_ptr<uint8_t[]> sig(new uint8_t[sig_length]);
    std::unique_ptr<uint8_t[]> sig_base64(
        new uint8_t[olm::encode_base64_length(sig_length)]);

    if (std::size_t(-1) !=
        acct->sign(message, message_length, sig.get(), sig_length)) {
      olm::encode_base64(sig.get(), sig_length, sig_base64.get());
      std::string signature(reinterpret_cast<const char *>(sig_base64.get()));

      signed_key = {{"signed_curve25519:" + key.begin().key(),
                     {{to_sign.begin().key(), to_sign.begin().value()},
                      {"signatures",
                       {{user_id_, {{"ed25519:" + device_id_, signature}}}}}}}};
      return signed_key;
    } else {
      // Couldnt sign properly, return nullptr to signify this
      return nullptr;
    }
  } catch (const json::exception &e) {
    std::cout
        << "Encountered an issue during json serialization/deserialization: "
        << std::endl
        << e.what() << std::endl;
    return nullptr;
  } catch (const std::exception &e) {
    std::cout << "Encountered an issue during key signing: " << std::endl
              << e.what() << std::endl;
    return nullptr;
  }
}

/*
 * Returns the number of keys which were generated and signed
 * Upon successful return, data will contain the signed keys and num_keys will
 * be returned Upon error, data will be restored to its original state, and 0
 * will be returned
 */
int MatrixOlmWrapper::genSignedKeys(json &data, int num_keys) {
  int rand_length = acct->generate_one_time_keys_random_length(num_keys);
  std::unique_ptr<uint8_t[]> rand_data = getRandData(rand_length);
  json original_data = data;
  try {

    if (std::size_t(-1) !=
        acct->generate_one_time_keys(num_keys, rand_data.get(), rand_length)) {
      int keys_size = acct->get_one_time_keys_json_length();
      std::unique_ptr<uint8_t[]> keys(new uint8_t[keys_size]);

      if (std::size_t(-1) !=
          acct->get_one_time_keys_json(keys.get(), keys_size)) {
        json one_time_keys = json::parse(
            std::string(reinterpret_cast<const char *>(keys.get())));

        json signed_key;
        for (auto it = one_time_keys["curve25519"].begin();
             it != one_time_keys["curve25519"].end(); ++it) {
          json key;
          key[it.key()] = it.value();
          if ((signed_key = signKey(key)) == nullptr) {
            data = original_data;
            return 0;
          }
          data["one_time_keys"][signed_key.begin().key()] =
              signed_key.begin().value();
        }

        return num_keys;
      } else {
        // Couldnt retrieve one time keys
        data = original_data;
        return 0;
      }
    } else {
      // Couldnt generate one time keys
      data = original_data;
      return 0;
    }
  } catch (const json::exception &e) {
    std::cout
        << "Encountered an issue during json serialization/deserialization: "
        << std::endl
        << e.what() << std::endl;
    data = original_data;
    return 0;
  } catch (const std::exception &e) {
    std::cout << "Encountered an issue during signed key generation: "
              << std::endl
              << e.what() << std::endl;
    data = original_data;
    return 0;
  }
}

// TODO add synchronization
void MatrixOlmWrapper::replenishKeyJob() {
  try {
    // Call upload keys to figure out how many keys are present
    std::string empty = "{}";
    uploadKeys(empty, [this](const std::string &key_counts,
                             std::experimental::optional<std::string>) {
      int current_key_count = 0;
      if (!key_counts.empty() &&
          json::parse(key_counts).count("one_time_key_counts") == 1) {
        current_key_count =
            json::parse(key_counts)["one_time_key_counts"]["signed_curve25519"]
                .get<int>();
      }

      int keys_needed = static_cast<int>(acct->max_number_of_one_time_keys()) -
                        current_key_count;

      if (keys_needed) {
        json data;
        if (genSignedKeys(data, keys_needed) > 0 && uploadKeys != nullptr) {
          std::string data_string = data.dump(2);
          uploadKeys(
              data_string, [this, current_key_count](
                               const std::string &resp,
                               std::experimental::optional<std::string> err) {
                if (!err) {
                  std::cout << "publishing one time keys returned: " << resp
                            << std::endl;
                  if (json::parse(
                          resp)["one_time_key_counts"]["signed_curve25519"]
                          .get<int>() > current_key_count) {
                    acct->mark_keys_as_published();
                  }
                }
              });
        }
      }
    });
  } catch (const json::exception &e) {
    std::cout
        << "Encountered an issue during json serialization/deserialization: "
        << std::endl
        << e.what() << std::endl;
    return;
  } catch (const std::exception &e) {
    std::cout << "Encountered an issue during key replenishment: " << std::endl
              << e.what() << std::endl;
    return;
  }
}

std::unique_ptr<olm::Account>
MatrixOlmWrapper::loadAccount(std::string keyfile_path,
                              std::string keyfile_pass) {
  std::unique_ptr<olm::Account> acct = std::make_unique<olm::Account>();
  if (keyfile_path == "" && keyfile_pass == "") {
    int random_size = acct->new_account_random_length();
    std::unique_ptr<uint8_t[]> random = getRandData(random_size);

    if (std::size_t(-1) != acct->new_account(random.get(), random_size)) {
      std::thread([this]() {
        while (true) {
          setupIdentityKeys();
          if (id_published) {
            replenishKeyJob();
          }
          std::this_thread::sleep_for(std::chrono::minutes(10));
        }
      })
          .detach();

      return acct;
    } else {
      // Error occurred, throw exception
      return nullptr;
    }
  } else {
    // Stubbed functionality
    return nullptr;
  }
}
