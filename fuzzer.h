#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <ctime>
#include <curl/curl.h>

struct RequestData {
    std::string url;
    std::string response;
    long httpCode = 0;
};

// structur for individual curl handle
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output);

class Fuzzer {
private:
  bool running;
  // user inpuit
  bool verbosity;
  std::string speed;
  std::string fuzzing;
  std::string url;
  std::string wordlistPath;
  std::string userInfo;
  bool validateURL(const std::string& url);

  void initVariables();

public:
  Fuzzer();
  // assign wordlist file to vector
  const std::vector<std::string> getWordlist(std::string filePath);
  // user input
  std::vector<std::string> getUserWordlist() const;
  void captureFlags(int argc, char* argv[]);

  // fuzzing
  void defaultFuzzing();
  void backupFileFuzzing();

  void run();
};
