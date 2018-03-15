#include "MatrixOlmCpp.hpp"
#include <stdlib.h>

OlmAccount *MatrixOlmCpp::loadAccount(std::string keyfile_path,
                                    std::string keyfile_pass) {
  if (keyfile_path == "" && keyfile_pass == "") {
    void *memory = malloc(olm_account_size());
    if (memory) {
      return olm_account(memory);
    } else {
      return nullptr;
    }
  } else {
    // Stubbed functionality
    void *memory = malloc(olm_account_size());
    if (memory) {
      return olm_account(memory);
    } else {
      return nullptr;
    }
  }
}
