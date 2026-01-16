rm -rf build
mkdir build
cd build
cmake -DSYMCC_RT_BACKEND=qsym -DZ3_DIR=/home/aaa/LLM-SMT/z3-4.14.1/install/lib/cmake/z3 ..
make -j4
