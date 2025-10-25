#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <algorithm>

// LiteRT 헤더
#include "tensorflow/lite/interpreter.h"
#include "tensorflow/lite/kernels/register.h"
#include "tensorflow/lite/model.h"

// OpenCV 헤더
#include "opencv2/opencv.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <path/to/model.tflite>" << " <path/to/test_image/dir>" << '\n';
        return 1;
    }
    // --- 1. 설정 및 경로 정의 ---
    const std::string model_path = argv[1];
    const std::string image_path = argv[2];

    std::cout << "Model path: " << model_path << '\n';
    std::cout << "Dataset path: " << image_path << '\n';

    const std::string id[10] = {"Airplane", "Automobile", "Bird", "Cat", "Deer", "Dog", "Frog", "Horse", "Ship", "Truck"};

    // 모델 입력 사양 (CIFAR-10)
    const int input_height = 32;
    const int input_width = 32;
    const int num_classes = 10;

    // --- 2. TFLite 모델 초기화 ---
    std::unique_ptr<tflite::FlatBufferModel> model = tflite::FlatBufferModel::BuildFromFile(model_path.c_str());
    tflite::ops::builtin::BuiltinOpResolver resolver;
    std::unique_ptr<tflite::Interpreter> interpreter;
    tflite::InterpreterBuilder(*model, resolver)(&interpreter);
    interpreter->AllocateTensors();
    float* input_tensor = interpreter->typed_input_tensor<float>(0);
    float* output_tensor = interpreter->typed_output_tensor<float>(0);
    std::cout << "✅ TFLite model initialized." << std::endl;
    
    // --- 3. 추론 ---
    // a. 이미지 로드 및 전처리 (OpenCV)
    cv::Mat image = cv::imread(image_path, cv::IMREAD_COLOR);

    cv::Mat rgb_image, float_image;
    cv::cvtColor(image, rgb_image, cv::COLOR_BGR2RGB);
    rgb_image.convertTo(float_image, CV_32FC3, 1.0 / 255.0); // 0-1 정규화

    // b. 입력 텐서에 데이터 복사
    memcpy(input_tensor, float_image.data, sizeof(float) * input_width * input_height * 3);

    // c. 추론 실행
    interpreter->Invoke();

    // d. 결과 분석
    auto max_elem = std::max_element(output_tensor, output_tensor + num_classes);
    int predicted_label_idx = std::distance(output_tensor, max_elem);

    // --- 4. 최종 결과 출력 ---
    std::cout << "\n--- 🎯 Final Result ---" << std::endl;
    std::cout << "Inferenced ID: " << id[predicted_label_idx] << std::endl;
    std::cout << "----------------------" << std::endl;

    return 0;
}