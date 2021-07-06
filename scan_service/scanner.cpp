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

int scan_directory(const char* directory_path, ScannerResults& results)
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

  results.n_searched = n_searched;
  results.n_errors = n_errors;
  results.n_js_detects = n_js_detects;
  results.n_unix_detects = n_unix_detects;
  results.n_macos_detects = n_macos_detects;
  results.duration_s = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
  results.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
  results.duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000;

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
