#include "MatrixOlmWrapper.hpp"
#include <json.hpp>

#include <chrono>
#include <thread>

#include <stdlib.h>
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

using json = nlohmann::json;

void *getRandData(int buffer_size) {
  void *buffer = malloc(buffer_size);
  if (!buffer) {
    return nullptr;
  }

    // TODO: add other options to generate random data for different OSs
#ifdef __linux__
  int fd;
  if ((fd = open("/dev/random", O_RDONLY)) != -1) {
    read(fd, buffer, buffer_size);
    close(fd);
    return buffer;
  } else {
    std::cout << "Failed to open /dev/random" << std::endl;
    free(buffer);
    return nullptr;
  }
#endif
}

void MatrixOlmWrapper::setupIdentityKeys() {
  if (!id_published) {
    if (identity_keys_.empty()) {
      int id_buff_size = olm_account_identity_keys_length(acct);
      void *id_buff = malloc(id_buff_size);
      if (id_buff && olm_error() != olm_account_identity_keys(acct, id_buff,
                                                              id_buff_size)) {
        identity_keys_ = std::string(static_cast<char *>(id_buff));
      }
      free(id_buff);
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

void MatrixOlmWrapper::replenishKeyJob() {
  std::cout << "Replenishing one-time keys" << std::endl;
}

OlmAccount *MatrixOlmWrapper::loadAccount(std::string keyfile_path,
                                          std::string keyfile_pass) {
  OlmAccount *acct;
  if (keyfile_path == "" && keyfile_pass == "") {
    void *memory = malloc(olm_account_size());
    if (memory) {
      void *random;
      int random_size;

      acct = olm_account(memory);
      random_size = olm_create_account_random_length(acct);
      if ((random = getRandData(random_size)) != nullptr &&
          olm_error() != olm_create_account(acct, random, random_size)) {

        std::thread([this]() {
          while (true) {
            setupIdentityKeys();
            if (id_published) {
              replenishKeyJob();
            }
            std::this_thread::sleep_for(std::chrono::seconds(10));
          }
        })
            .detach();

        free(random);
        return acct;
      }

      free(memory);
      free(random);
      return nullptr;
    } else {
      return nullptr;
    }
  } else {
    // Stubbed functionality
    return nullptr;
  }
}
