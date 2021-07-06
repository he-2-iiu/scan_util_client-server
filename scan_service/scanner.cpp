#include "scanner.h"

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <mutex>

constexpr unsigned thread_max = 4;
static std::atomic<unsigned> available_threads = thread_max;
static std::condition_variable cv;

static std::atomic<size_t> n_errors{};
static std::atomic<size_t> n_js_detects{};
static std::atomic<size_t> n_unix_detects{};
static std::atomic<size_t> n_macos_detects{};

static void inspect_file_task(const std::filesystem::directory_entry& entry);

int scan_directory(const char* directory_path, size_t results[])
{
  std::filesystem::path dir_path{ directory_path };
  if (!std::filesystem::exists(dir_path)) {
    return SCANNER_ERROR_NO_DIR;
  }
  if (!std::filesystem::is_directory(dir_path)) {
    return SCANNER_ERROR_NO_DIR;
  }
  {
    std::ifstream dir{ dir_path };
    if (!dir.is_open()) {
      return SCANNER_ERROR_NO_PERMISSIONS;
    }
  }

  size_t n_searched{};
  std::vector<std::thread> tasks{};
  tasks.reserve(thread_max);
  std::mutex m{};
  std::unique_lock<std::mutex> lock{ m };

  auto start{ std::chrono::high_resolution_clock::now() };

  for (const auto& entry : std::filesystem::directory_iterator{ dir_path,
                                                                std::filesystem::directory_options::skip_permission_denied }) {
    ++n_searched;
    cv.wait(lock, [&] {
      return available_threads > 0;
    });
    --available_threads;
    tasks.emplace_back(std::thread(inspect_file_task, entry));
  }

  for (auto& thread : tasks)
    thread.join();

  auto duration{ std::chrono::high_resolution_clock::now() - start };

  results[ScannerResultsTypes::Searched] = n_searched;
  results[ScannerResultsTypes::Errors] = n_errors;
  results[ScannerResultsTypes::JsDetects] = n_js_detects;
  results[ScannerResultsTypes::UnixDetects] = n_unix_detects;
  results[ScannerResultsTypes::MacosDetects] = n_macos_detects;
  results[ScannerResultsTypes::DurationS] = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
  results[ScannerResultsTypes::DurationMs] = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
  results[ScannerResultsTypes::DurationUs] = std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000;

  n_errors = 0;
  n_js_detects = 0;
  n_unix_detects = 0;
  n_macos_detects = 0;

  return SCANNER_SUCCESS;
}

static void inspect_file_task(const std::filesystem::directory_entry& entry)
{
  std::ifstream file{ entry.path() };
  if (!file.is_open()) {
    ++n_errors;
    ++available_threads;
    cv.notify_all();
    return;
  }

  const char* js_suspicious{ "<script>evil_script()</script>" };
  const char* unix_suspicious{ "rm -rf ~/Documents" };
  const char* macos_suspicious{ "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")" };

  std::string line;
  const auto& extension = entry.path().extension().string();

  while (getline(file, line)) {
    if (extension == ".js" && line.find(js_suspicious) != std::string::npos) {
      ++n_js_detects;
      break;
    }
    if (line.find(unix_suspicious) != std::string::npos) {
      ++n_unix_detects;
      break;
    }
    if (line.find(macos_suspicious) != std::string::npos) {
      ++n_macos_detects;
      break;
    }
  }
  ++available_threads;
  cv.notify_all();
}
