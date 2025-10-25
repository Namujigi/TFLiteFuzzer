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

#define TOSTRING(x) x
const std::string PROJECT_ROOT = TOSTRING(PROJECT_ROOT_PATH);

// CSV 파일에서 (이미지 경로, 라벨) 목록을 읽는 함수
std::vector<std::pair<std::string, int>> load_dataset_from_csv(
    const std::string& csv_path, const std::string& image_dir) {
    
    std::vector<std::pair<std::string, int>> dataset;
    std::ifstream file(csv_path);
    std::string line;

    // 헤더 라인 건너뛰기
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string filename, label_str;
        
        std::getline(ss, filename, ',');
        std::getline(ss, label_str, ',');
        
        dataset.push_back({image_dir + "/" + filename, std::stoi(label_str)});
    }
    return dataset;
}

int main() {
    // --- 1. 설정 및 경로 정의 ---
    const std::string model_path = PROJECT_ROOT + "/model.tflite";
    const std::string image_dir = PROJECT_ROOT + "/cifar10_test_dataset/cifar10_test_images";
    const std::string csv_path = PROJECT_ROOT + "/cifar10_test_dataset/labels.csv";

    std::cout << "Model path: " << model_path << '\n';
    std::cout << "Dataset path: " << image_dir << '\n';

    // 모델 입력 사양 (CIFAR-10)
    const int input_height = 32;
    const int input_width = 32;
    const int num_classes = 10;

    // --- 2. 데이터셋 정보 로드 ---
    auto test_dataset = load_dataset_from_csv(csv_path, image_dir);
    if (test_dataset.empty()) {
        std::cerr << "Failed to load dataset from " << csv_path << std::endl;
        return -1;
    }
    std::cout << "✅ Loaded " << test_dataset.size() << " test images info." << std::endl;

    // --- 3. TFLite 모델 초기화 ---
    std::unique_ptr<tflite::FlatBufferModel> model = tflite::FlatBufferModel::BuildFromFile(model_path.c_str());
    tflite::ops::builtin::BuiltinOpResolver resolver;
    std::unique_ptr<tflite::Interpreter> interpreter;
    tflite::InterpreterBuilder(*model, resolver)(&interpreter);
    interpreter->AllocateTensors();
    float* input_tensor = interpreter->typed_input_tensor<float>(0);
    float* output_tensor = interpreter->typed_output_tensor<float>(0);
    std::cout << "✅ TFLite model initialized." << std::endl;
    
    // --- 4. 추론 및 정확도 계산 ---
    int correct_predictions = 0;
    int total_images = test_dataset.size();

    for (int i = 0; i < total_images; ++i) {
        const auto& [image_path, true_label_idx] = test_dataset[i];

        // a. 이미지 로드 및 전처리 (OpenCV)
        cv::Mat image = cv::imread(image_path, cv::IMREAD_COLOR);
        if (image.empty()) continue;

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

        if (predicted_label_idx == true_label_idx) {
            correct_predictions++;
        }
    }

    // --- 5. 최종 결과 출력 ---
    double accuracy = static_cast<double>(correct_predictions) / total_images * 100.0;
    std::cout << "\n--- 🎯 Final Result ---" << std::endl;
    std::cout << "Accuracy: " << std::fixed << std::setprecision(2) << accuracy << "%" << std::endl;
    std::cout << "----------------------" << std::endl;

    return 0;
}