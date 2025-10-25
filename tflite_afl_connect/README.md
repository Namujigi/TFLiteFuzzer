# Installation
<br>

``` bash
mkdir include
mkdir lib_release
mkdir lib_debug
```
<br>

### 1. Google FlatBuffers (v25.9.23)
``` bash
# Release Mode
git clone -b v25.9.23 --single-branch https://github.com/google/flatbuffers.git
cd flatbuffers
cp -r ./include/flatbuffers <project_root_dir>/include/flatbuffers

# 빌드 및 설치 (cmake version 3.28.3)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

cp ./libflatbuffers.a <project_root_dir>/lib_release/libflatbuffers.a
```
``` bash
# Debug Mode
mkdir debug_build && cd debug_build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
cp ./libflatbuffers.a <project_root_dir>/lib_debug/libflatbuffers.a
```
<br>

### 2. TensorFlow lite (v2.20.0)
``` bash
# LiteRT CMAKE 오류로 다른 방법 선택.
# Release Mode
git clone -b v2.20.0 --single-branch https://github.com/tensorflow/tensorflow.git tensorflow_src
cd tensorflow_src
cp -r ./tensorflow <project_root_dir>/include/tensorflow

./configure # 웬만하면 모두 Default로 설정하고, 추가 옵션에 대해 모두 No로. 컴파일 옵션은 -O3
						
bazel build -c opt --cxxopt='--std=c++17' --fat_apk_cpu=x86_64 tensorflow/lite:libtensorflowlite.so
# ./tensorflow_src/bazel-bin/tensorflow/lite/libtensorflowlite.so가 생성됨
# --fat_apk_cpu=x86_64는 Linux machine을 위한 옵션.

cp ./bazel-bin/tensorflow/lite/libtensorflowlite.so <project_root_dir>/lib_release/libtensorflowlite.so
```
``` bash
# Debug Mode
mkdir debug_tensorflow_src && cd debug_tensorflow_src
./configure

bazel build tensorflow/lite:libtensorflowlite.so \
    --cxxopt="--std=c++17" \
    --compilation_mode=opt \
    --copt="-g" \
    --strip=never

cp ./bazel-bin/tensorflow/lite/libtensorflowlite.so <project_root_dir>/lib_debug/libtensorflowlite.so
```
<br>

## Build & Run Example

### TFLite AFL Connect build
```bash
mkdir build
cd bulid

cmake ..
cmake --build . -j$(nproc)
```