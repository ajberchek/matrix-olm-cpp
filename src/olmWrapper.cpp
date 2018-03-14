#include "olmWrapper.hpp"
#include <stdlib.h>

OlmAccount *olmWrapper::loadAccount(std::string keyfile_path,
                                    std::string keyfile_pass) {
  if (keyfile_path == "" && keyfile_pass == "") {
    void *memory = (int *)malloc(olm_account_size());
    if (memory) {
      return olm_account(memory);
    } else {
      return nullptr;
    }
  } else {
    // Stubbed functionality
    void *memory = (int *)malloc(olm_account_size());
    if (memory) {
      return olm_account(memory);
    } else {
      return nullptr;
    }
  }
}
