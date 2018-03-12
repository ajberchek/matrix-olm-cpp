include(ExternalProject)

#
# Build & install olm.
#

set(THIRD_PARTY_ROOT ${CMAKE_SOURCE_DIR}/.third-party)
set(OLM_ROOT ${THIRD_PARTY_ROOT}/olm)

ExternalProject_Add(
  Olm

  GIT_REPOSITORY https://git.matrix.org/git/olm.git
  GIT_TAG master

  BUILD_IN_SOURCE 1
  SOURCE_DIR ${OLM_ROOT}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make static
  INSTALL_COMMAND ""
)

include_directories(SYSTEM ${OLM_ROOT}/include ${OLM_ROOT}/include/olm)
link_directories(${OLM_ROOT}/build)
