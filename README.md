# Matrix Olm C++ Wrapper

## Description
This repo provides a C++ wrapper for the library, [libolm](https://git.matrix.org/git/olm/), used in Matrix's end-to-end encryption.

## Build Instructions

**Dependencies**

- CMake 3.1 or greater
- C++ 11 compiler
- Clang format 3.5
- [Libsodium](https://download.libsodium.org/doc/)
- GoogleTest [Install Guide for Ubuntu](https://www.eriksmistad.no/getting-started-with-google-test-on-ubuntu/)
- Libolm (Automatically downloaded and integrated during build)

**Building**

To build the library, simply run `make`

**Testing**

To test the library, simplpy run `make test`

## Contributing Instructions

- Please consult the design document to see what functionality needs to be implemented.
- Please run `make lint` before submitting a PR

## Credits

The code in this repository could not have been possible without the following

- Code and design inspiration from [mujx/mtxclient](https://github.com/mujx/mtxclient) by Konstantinos Sideris (AKA mujx)
- Implementation advice from mujx, kitsune, anoa, Matthew, and other members of the matrix community
