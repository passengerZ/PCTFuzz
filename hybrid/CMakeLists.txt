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

set(LLVM_VERSION "" CACHE STRING "LLVM version to use. The corresponding LLVM dev package must be installed.")
set(HybridFuzzer_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

set(HybridFuzzerSrc
  ${HybridFuzzer_SRC_DIR}/HybridFuzzer.cpp
)

add_executable(HybridFuzzer ${HybridFuzzerSrc})

target_include_directories(HybridFuzzer PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}     # for our fake pin.H and Runtime.h
  ${SYMCC_RT_INCLUDE_DIR}) # for common runtime components

target_include_directories(HybridFuzzer SYSTEM PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR})

# We need to get the LLVM support component for llvm::APInt.
llvm_map_components_to_libnames(QSYM_LLVM_DEPS support)

set(HybridFuzzerDeps
    ${QSYM_LLVM_DEPS})

target_link_libraries(HybridFuzzer ${HybridFuzzerDeps})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Filesystem COMPONENTS Final Experimental)
target_link_libraries(HybridFuzzer std::filesystem)