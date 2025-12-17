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
# with SymCC. If not, see <https://www.gnu.org/licenses/>.

# Build the parts of the Qsym backend that are relevant for us

set(QSYM_SOURCE_DIR ${CMAKE_SOURCE_DIR}/expr)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
-Wredundant-decls -Wcast-align \
-Wmissing-include-dirs -Wswitch-default \
-Wextra -Wall -Winvalid-pch -Wredundant-decls -Wformat=2 \
-Wmissing-format-attribute -Wformat-nonliteral -Wno-unused-parameter")

if (NOT DEFINED LLVM_VERSION)
  message(FATAL_ERROR "LLVM version must be specified with the LLVM_VERSION variable.")
endif()

find_package(LLVM ${LLVM_VERSION} REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

# Qsym doesn't work with old versions of Z3
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

set(QsymExprSrc
  ${QSYM_SOURCE_DIR}/expr.cpp
  ${QSYM_SOURCE_DIR}/expr_builder.cpp
  ${QSYM_SOURCE_DIR}/expr_cache.cpp
  ${QSYM_SOURCE_DIR}/expr_evaluate.cpp
  ${QSYM_SOURCE_DIR}/solver.cpp
  ${QSYM_SOURCE_DIR}/dependency.cpp
  ${QSYM_SOURCE_DIR}/logging.cpp
  ${QSYM_SOURCE_DIR}/afl_trace_map.cpp
  ${QSYM_SOURCE_DIR}/allocation.cpp
  ${QSYM_SOURCE_DIR}/call_stack_manager.cpp
  ${QSYM_SOURCE_DIR}/range.cpp
  ${QSYM_SOURCE_DIR}/xxhash.cpp)

add_library(QsymExprObj OBJECT ${QsymExprSrc})

set_property(TARGET QsymExprObj PROPERTY POSITION_INDEPENDENT_CODE 1)

target_include_directories(QsymExprObj SYSTEM PRIVATE
  ${Z3_CXX_INCLUDE_DIRS}        # for Z3 support
  ${QSYM_SOURCE_DIR})