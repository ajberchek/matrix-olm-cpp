#include "MatrixOlmWrapper.hpp"

#include <chrono>
#include <memory>
#include <thread>

#include <stdlib.h>
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

// buffer_size is the size of the buffer in number of bytes
std::unique_ptr<uint8_t[]> getRandData(unsigned int buffer_size) {
  std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_size]);

  // TODO: add other options to generate random data for different OSs
#ifdef __linux__
  int fd;
  if ((fd = open("/dev/random", O_RDONLY)) != -1) {
    unsigned int bytes_read = 0;
    while (bytes_read < buffer_size) {
      bytes_read +=
          read(fd, &(buffer.get()[bytes_read]), buffer_size - bytes_read);
    }
    close(fd);
    return buffer;
  } else {
    std::cout << "Failed to open /dev/random" << std::endl;
    return nullptr;
  }
#endif
}

void MatrixOlmWrapper::setupIdentityKeys() {
  if (!id_published) {
    if (identity_keys_.empty()) {
      int id_buff_size = olm_account_identity_keys_length(acct);
      std::unique_ptr<uint8_t[]> id_buff(new uint8_t[id_buff_size]);
      if (olm_error() !=
          olm_account_identity_keys(acct, id_buff.get(), id_buff_size)) {
        identity_keys_ =
            std::string(reinterpret_cast<const char *>(id_buff.get()));
      }
    }

    // Form json and publish keys
    if (!identity_keys_.empty() && uploadKeys != nullptr) {
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
    }
  }
}

// key should contain one key formatted as follows {"<key_id>":
// "<curve25519_key>"}
json MatrixOlmWrapper::signKey(json &key) {
  int sig_length, message_length;
  void const *message;
  json to_sign, signed_key;

  to_sign["key"] = key.begin().value();
  signed_key = json::parse("{}");

  std::string m = to_sign.dump(2);
  message_length = m.size();
  message = static_cast<void const *>(m.c_str());
  sig_length = olm_account_signature_length(acct);
  std::unique_ptr<uint8_t[]> sig(new uint8_t[sig_length]);

  if (olm_error() !=
      olm_account_sign(acct, message, message_length, sig.get(), sig_length)) {
    std::string signature =
        std::string(reinterpret_cast<const char *>(sig.get()));
    signed_key = {{"signed_curve25519:" + key.begin().key(),
                   {{to_sign.begin().key(), to_sign.begin().value()},
                    {"signatures",
                     {{user_id_, {{"ed25519:" + device_id_, signature}}}}}}}};
  }
  return signed_key;
}

// Returns the number of keys which were generated and signed
// Upon successful return, data will contain the signed keys
int MatrixOlmWrapper::genSignedKeys(json &data, int num_keys) {
  int generated_keys = 0;
  int rand_length =
      olm_account_generate_one_time_keys_random_length(acct, num_keys);
  std::unique_ptr<uint8_t[]> rand_data = getRandData(rand_length);
  data = json::parse("{}");

  if (olm_error() != olm_account_generate_one_time_keys(
                         acct, num_keys, rand_data.get(), rand_length)) {
    int keys_size = olm_account_one_time_keys_length(acct);
    std::unique_ptr<uint8_t[]> keys(new uint8_t[keys_size]);

    if (olm_error() != olm_account_one_time_keys(acct, keys.get(), keys_size)) {
      json one_time_keys =
          json::parse(std::string(reinterpret_cast<const char *>(keys.get())));
      for (auto it = one_time_keys["curve25519"].begin();
           it != one_time_keys["curve25519"].end(); ++it) {
        json key;
        key[it.key()] = it.value();
        json signed_key = signKey(key);
        data["one_time_keys"][signed_key.begin().key()] =
            signed_key.begin().value();
      }
      generated_keys = num_keys;
    }
  }
  return generated_keys;
}

// TODO add synchronization
void MatrixOlmWrapper::replenishKeyJob() {
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

    int keys_needed =
        static_cast<int>(olm_account_max_number_of_one_time_keys(acct)) -
        current_key_count;
    // Used until new random number generation is in place since /dev/random
    // takes a long time to generate random data
    keys_needed = 2;

    json data;
    if (genSignedKeys(data, keys_needed) > 0 && uploadKeys != nullptr) {
      std::string data_string = data.dump(2);
      uploadKeys(
          data_string, [this, current_key_count](
                           const std::string &resp,
                           std::experimental::optional<std::string> err) {
            if (!err) {
              std::cout << "publishing one time keys returned " << resp
                        << std::endl;
              if (json::parse(resp)["one_time_key_counts"]["signed_curve25519"]
                      .get<int>() > current_key_count) {
                olm_account_mark_keys_as_published(acct);
              }
            }
          });
    }
  });
}

OlmAccount *MatrixOlmWrapper::loadAccount(std::string keyfile_path,
                                          std::string keyfile_pass) {
  OlmAccount *acct;
  if (keyfile_path == "" && keyfile_pass == "") {
    std::unique_ptr<uint8_t[]> memory(new uint8_t[olm_account_size()]);
    std::unique_ptr<uint8_t[]> random;
    int random_size;

    acct = olm_account(memory.get());
    random_size = olm_create_account_random_length(acct);
    random = getRandData(random_size);
    if (olm_error() != olm_create_account(acct, random.get(), random_size)) {

      std::thread([this]() {
        while (true) {
          setupIdentityKeys();
          if (id_published) {
            replenishKeyJob();
          }
          std::this_thread::sleep_for(std::chrono::minutes(1));
        }
      })
          .detach();

      return acct;
    }

    return nullptr;
  } else {
    // Stubbed functionality
    return nullptr;
  }
}
