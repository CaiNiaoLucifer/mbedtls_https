### install 
add USE_SHARED_MBEDTLS_LIBRARY will create shared library
```
mkdir build
cd build
cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On ..
make
make install
```

### compile the https demo
```
cd build/programs/https/
make
```
