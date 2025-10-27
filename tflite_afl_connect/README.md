# Installation
<br>

``` bash
mkdir include
mkdir lib_release
mkdir lib_debug
mkdir build_release
mkdir build_debug
```
<br>

### 1. Google FlatBuffers (v25.9.23)
``` bash
# Release Mode
git clone -b v25.9.23 --single-branch https://github.com/google/flatbuffers.git
cd flatbuffers
cp -r ./include/flatbuffers ../include/flatbuffers

# 빌드 및 설치 (cmake version 3.28.3)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

cp ./libflatbuffers.a ../../lib_release/libflatbuffers.a
```
``` bash
# Debug Mode
mkdir debug_build && cd debug_build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
cp ./libflatbuffers.a ../../lib_debug/libflatbuffers.a

nm ../../lib_debug/libflatbuffers.a
# 심볼 있는지 확인하여 Debug info 확인.
```
<br>

### 2. TensorFlow lite (v2.20.0)
``` bash
# LiteRT CMAKE 오류로 다른 방법 선택.
# Release Mode
git clone https://github.com/tensorflow/tensorflow.git tensorflow_src
cd tensorflow_src
cp -r ./tensorflow ../include/tensorflow

./configure # 웬만하면 모두 Default로 설정하고, 추가 옵션에 대해 모두 No로. 컴파일 옵션은 -O3
						
bazel build -c opt --cxxopt='--std=c++17' --fat_apk_cpu=x86_64 tensorflow/lite:libtensorflowlite.so
# ./tensorflow_src/bazel-bin/tensorflow/lite/libtensorflowlite.so가 생성됨
# --fat_apk_cpu=x86_64는 Linux machine을 위한 옵션.

cp ./bazel-bin/tensorflow/lite/libtensorflowlite.so ../lib_release/libtensorflowlite.so
```
``` bash
# Debug Mode
bazel clean --expunge

./configure # 웬만하면 모두 Default로 설정하고, 추가 옵션에 대해 모두 No로.
            # 컴파일 옵션은 Enter로 Default 설정.

bazel build tensorflow/lite:libtensorflowlite.so \
  --cxxopt="--std=c++17" \
	--cxxopt="-g3" \
  --cxxopt="-ggdb" \
  --cxxopt="-O0" \
  --compilation_mode=dbg \
  --strip=never \
  --per_file_copt="+.*@-g3"

cp ./bazel-bin/tensorflow/lite/libtensorflowlite.so ../lib_debug/libtensorflowlite.so

file ../lib_debug/libtensorflowlite.so
# ... with debug_info, not stripped 확인
```
<br>

## Build & Run Example

### AFL++ Docker Installation
```bash
docker pull aflplusplus/aflplusplus
# docker pull namujigi2/aflplusplus_for_tflitefuzzer:latest

docker run -it --name afl --user root \
		-v /home/username/TFLiteFuzzer:/home/aflplusplus \
		aflplusplus/aflplusplus # namujigi2/aflplusplus_for_tflitefuzzer:latest
```
```bash
apt-get update && apt-get install libopencv-dev -y

cd ~
git clone https://github.com/pwndbg/pwndbg.git
cd pwndbg
./setup.sh

cd /AFLplusplus/include
vi config.h
```
```cpp
-#define MAX_FILE (1 * 1024 * 1024L)
+#define MAX_FILE (64 * 1024 * 1024L)
```
```bash
cd ..
make clean all
make install

export AFL_TESTCACHE_SIZE=128
```

<br>

### Release Mode Build & Fuzzing in AFL++ Docker
```bash
# CMakeLists_Release.txt -> CMakeLists.txt로 변경
cd /home/username/TFLiteFuzzer/tflite_afl_connect/build_release

cmake ..
cmake --build . -j$(nproc)
```
```bash
cd /home/username/TFLiteFuzzer/tflite_afl_connect/build_release

afl-fuzz -i ../examples/ -o ../out/ -s 123 -G 30000000 -t 3600000 \
 -- ./release_mode @@ ../../tflite_cpp_api_test/cifar10_test_dataset/cifar10_test_images/00000.png
```

<br>

### Debug Mode Build & Debugging using Pwndbg
```bash
# CMakeLists.txt -> CMakeLists.txt로 변경
cd /home/username/TFLiteFuzzer/tflite_afl_connect/build_debug

cmake ..
cmake --build . -j$(nproc)
```
```bash
cd /home/username/TFLiteFuzzer/tflite_afl_connect

gdb ./build_debug/debug_mode

pwndbg> set substitute-path /proc/self/cwd /home/username/TFLiteFuzzer/tflite_afl_connect/tensorflow_src
pwndbg> dir .
pwndbg> dir ./tensorflow_src
```