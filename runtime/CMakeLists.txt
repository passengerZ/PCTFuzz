# This file is part of the SymCC runtime.
#
# The SymCC runtime is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# The SymCC runtime is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with the SymCC runtime. If not, see <https://www.gnu.org/licenses/>.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
-Wredundant-decls -Wcast-align \
-Wmissing-include-dirs -Wswitch-default \
-Wextra -Wall -Winvalid-pch -Wredundant-decls -Wformat=2 \
-Wmissing-format-attribute -Wformat-nonliteral -Wno-unused-parameter")

# Qsym doesn't work with old versions of Z3
option(Z3_TRUST_SYSTEM_VERSION "Use the system-provided Z3 without a version check" OFF)
find_package(Z3 4.5 CONFIG)
if (NOT Z3_FOUND)
  if (NOT Z3_TRUST_SYSTEM_VERSION)
    message(FATAL_ERROR "Couldn't locate Z3. \
If you want me to trust that a suitable version is available nonetheless, \
configure CMake with -DZ3_TRUST_SYSTEM_VERSION=on (see also docs/Configuration.txt).")
  else()
    if (EXISTS "/usr/include/z3")
      set(Z3_CXX_INCLUDE_DIRS "/usr/include/z3")
    else()
      set(Z3_CXX_INCLUDE_DIRS)
    endif()
    set(Z3_LIBRARIES "z3")
  endif()
endif()

#generate qsymExpr.pb.cc and qsymExpr.pb.h
#Note that cmake do not generate .cc and .h file at cmake stage, IT'S DONE ON BUILD STAGE!!
find_package(Protobuf REQUIRED config)
if(PROTOBUF_FOUND)
  message(STATUS "Found Protobuf, include dir " ${PROTOBUF_INCLUDE_DIRS} ",library dir " ${PROTOBUF_LIBRARIES})
else()
  message(FATAL_ERROR "Protobuf missing, try -DProtobuf_DIR -DProtobuf_LIBRARIES -DProtobuf_INCLUDE_DIR")
endif()

message(STATUS "adding include dir,  ${CMAKE_CURRENT_BINARY_DIR}")
set(PROTO_INC_DIR ${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIRS} PARENT_SCOPE)
set(PROTOBUF_GENERATE_CPP_APPEND_PATH CMAKE_CURRENT_BINARY_DIR)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${CMAKE_SOURCE_DIR}/runtime/protobuf/qsymExpr.proto)
message(STATUS "protoc input : ${CMAKE_SOURCE_DIR}/runtime/protobuf/qsymExpr.proto")
message(STATUS "protoc output: ${PROTO_SRCS} ${PROTO_HDRS}")


set(LLVM_VERSION "" CACHE STRING "LLVM version to use. The corresponding LLVM dev package must be installed.")

# Place the final products in the top-level output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(SYMCC_RT_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(QSYM_SOURCE_DIR ${CMAKE_SOURCE_DIR}/expr)

# There is list(TRANSFORM ... PREPEND ...), but it's not available before CMake 3.12.
set(SymCCRtSrc
  ${SYMCC_RT_SRC_DIR}/Config.cpp
  ${SYMCC_RT_SRC_DIR}/RuntimeCommon.cpp
  ${SYMCC_RT_SRC_DIR}/LibcWrappers.cpp
  ${SYMCC_RT_SRC_DIR}/Shadow.cpp
  ${SYMCC_RT_SRC_DIR}/GarbageCollection.cpp
  ${SYMCC_RT_SRC_DIR}/Runtime.cpp
  ${PROTO_SRCS}
)

add_library(SymCCRtObj OBJECT
  ${SymCCRtSrc})

set_property(TARGET SymCCRtObj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(SymCCRtShared SHARED $<TARGET_OBJECTS:SymCCRtObj>)
add_library(SymCCRtStatic STATIC $<TARGET_OBJECTS:SymCCRtObj>)

target_include_directories(SymCCRtObj PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}     # for our fake pin.H and Runtime.h
  ${SYMCC_RT_INCLUDE_DIR}) # for common runtime components

target_include_directories(SymCCRtObj SYSTEM PRIVATE
  ${Z3_CXX_INCLUDE_DIRS}        # for Z3 support
  ${QSYM_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${PROTOBUF_INCLUDE_DIRS})

# We need to get the LLVM support component for llvm::APInt.
llvm_map_components_to_libnames(QSYM_LLVM_DEPS support)

set(SymCCRtDeps
    QsymExprObj
    ${Z3_LIBRARIES}
    ${QSYM_LLVM_DEPS}
    ${PROTOBUF_LIBRARIES})

# Object libraries cannot be linked directly, so we link the final libraries one by one
# https://gitlab.kitware.com/cmake/cmake/-/issues/18090
target_link_libraries(SymCCRtShared ${SymCCRtDeps})
target_link_libraries(SymCCRtStatic ${SymCCRtDeps})

# We use std::filesystem, which has been added in C++17. Before its official
# inclusion in the standard library, Clang shipped the feature first in
# libc++experimental and later in libc++fs; GCC used to require libstdc++fs. We
# make no attempt to support those older compiler versions, with one exception:
# some current LTS distributions ship a GCC that requires libstdc++fs for
# std::filesystem - we catch this case in order to enable users of such systems
# to build with the default compiler.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Filesystem COMPONENTS Final Experimental)
target_link_libraries(SymCCRtObj std::filesystem)



if (NOT TARGET SymCCRtStatic)
  message(FATAL_ERROR "The backend \"${SYMCC_RT_BACKEND}\" does not produce the target SymCCRtStatic.\
This is a bug and it should be reported. Please open PR to the symcc-rt repository.")
endif()

if (NOT TARGET SymCCRtShared)
  message(FATAL_ERROR "The backend \"${SYMCC_RT_BACKEND}\" does not produce the target SymCCRtShared.\
This is a bug and it should be reported. Please open PR to the symcc-rt repository.")
endif()

set_target_properties(SymCCRtStatic PROPERTIES OUTPUT_NAME "symcc-rt")
set_target_properties(SymCCRtShared PROPERTIES OUTPUT_NAME "symcc-rt")
