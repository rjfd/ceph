# Try to find spdk
#
# Once done, this will define
#
# SPDK_FOUND
# SPDK_INCLUDE_DIR
# SPDK_LIBRARIES

find_path(SPDK_INCLUDE_DIR spdk/nvme.h
  PATHS ${SPDK_ROOT_DIR}/include)
find_library(SPDK_nvme_LIBRARY spdk_nvme
  PATHS ${SPDK_ROOT_DIR}/lib/nvme)
find_library(SPDK_memory_LIBRARY spdk_memory
  PATHS ${SPDK_ROOT_DIR}/lib/memory)
find_library(SPDK_util_LIBRARY spdk_util
  PATHS ${SPDK_ROOT_DIR}/lib/util)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(spdk DEFAULT_MSG
  SPDK_INCLUDE_DIR
  SPDK_nvme_LIBRARY
  SPDK_memory_LIBRARY
  SPDK_util_LIBRARY)

if(SPDK_FOUND)
  set(SPDK_LIBRARIES
    ${SPDK_nvme_LIBRARY}
    ${SPDK_memory_LIBRARY}
    ${SPDK_util_LIBRARY})
endif(SPDK_FOUND)

mark_as_advanced(SPDK_INCLUDE_DIR SPDK_LIBRARIES)
