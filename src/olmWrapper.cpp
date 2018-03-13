#include "olmWrapper.hpp"
#include <stdlib.h>

std::unique_ptr<OlmAccount> olmWrapper::loadAccount(std::string keyfile_path,
                                                    std::string keyfile_pass) {
  if (keyfile_path == "" && keyfile_pass == "") {
    return std::unique_ptr<OlmAccount>(
        static_cast<OlmAccount *>(olm_account(malloc(olm_account_size()))));
  } else {
    // Stubbed functionality
    return std::unique_ptr<OlmAccount>(
        static_cast<OlmAccount *>(olm_account(malloc(olm_account_size()))));
  }
}
