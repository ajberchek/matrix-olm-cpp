#include "MatrixOlmWrapper.hpp"
#include <stdlib.h>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

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
        // Set up identity keys for this account
        int id_buff_size = olm_account_identity_keys_length(acct);
        void *id_buff = malloc(id_buff_size);
        if (id_buff && olm_error() != olm_account_identity_keys(acct, id_buff,
                                                                id_buff_size)) {
          identity_keys_ = std::string(static_cast<char *>(id_buff));
        }
        free(random);
        free(id_buff);
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
