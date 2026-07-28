# OpenSSL (libcrypto) example using CMake and Conan

This is taken from https://github.com/chrislattman/test-crypto but using CMake as the build system and Conan as the package manager.

How to run:

```
# One time only (install Conan):
python3 -m venv .venv
source .venv/bin/activate
pip install conan
conan profile detect --force

# Generate Makefiles, build, and run:
conan install . --output-folder=build --build=missing -s build_type=Debug
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cmake --build build --target run-tls
```
