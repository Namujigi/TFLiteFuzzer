# Installation
## Requirements
<br>

``` bash
mkdir include
mkdir lib
```
<br>

### 1. Google FlatBuffers (v25.9.23)
``` bash
git clone https://github.com/google/flatbuffers.git
cd flatbuffers
git checkout v25.9.23

# 빌드 및 설치 (cmake version 3.28.3)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
sudo ldconfig

# 설치 확인
flatc --version
# 출력: flatc version 25.9.23

cp ./libflatbuffers.a <project_root_dir>/lib/libflatbuffers.a
```
<br>

### 2. TensorFlow lite (v2.20.0)
``` bash
# LiteRT CMAKE 오류로 다른 방법 선택.
git clone https://github.com/tensorflow/tensorflow.git tensorflow_src
cd tensorflow_src
git checkout v2.20.0

./configure # 웬만하면 모두 Default로 설정하고, 추가 옵션에 대해 모두 No로. 컴파일 옵션은 -O3
						
bazel build -c opt --cxxopt='--std=c++17' --fat_apk_cpu=x86_64 tensorflow/lite:libtensorflowlite.so
# ./tensorflow_src/bazel-bin/tensorflow/lite/libtensorflowlite.so가 생성됨
# --fat_apk_cpu=x86_64는 Linux machine을 위한 옵션.

cp ./bazel-bin/tensorflow/lite/libtensorflowlite.so <project_root_dir>/lib/libtensorflowlite.so

cp -r ./tensorflow <project_root_dir>/include/tensorflow
```
<br>

## Build & Run Example

### TFLite C++ API build
```bash
mkdir build
cd bulid

cmake ..
cmake --build . -j$(nproc)
```

### TFLite C++ API run
``` bash
cd build
./run_test

# Model path: /home/username/TFLiteFuzzer/tflite_cpp_api/cifar10_model.tflite
# Dataset path: /home/username/TFLiteFuzzer/tflite_cpp_api/cifar10_test_dataset/cifar10_test_images
# ✅ Loaded 10000 test images info.
# INFO: Created TensorFlow Lite XNNPACK delegate for CPU.
# ✅ TFLite model initialized.
#
# --- 🎯 Final Result ---
# Accuracy: 10.02%
# ----------------------
```