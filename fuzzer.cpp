#include "fuzzer.h"
#include <map>

void Fuzzer::initVariables() {
  running = true;
  // user input
  verbosity = false;
  speed = "";
  fuzzing = "";
  url = "";
  wordlistPath = "";
  
  userInfo = "Usage: ./fuzzer -u <URL> [-w wordlist] [-flags]"
             "Options:"
             "\n\n\tGeneral:"
             "\n\t\t-u <URL>"
             "\n\t\t-v to increase verbosity"
             "\n\t\t-sD to decrease speed / request amount"
             "\n\t\t-sI to increase speed / request amount"
             "\n\n\tFuzzing:"
             "\n\t\t<none> deafult fuzzing (wordlist file path)"
             "\n\t\t-bf fuzzing for backup flie (no wordlist file path)"
             "\n";
}


// CURL
// meta data for request map
/*struct RequestData {*/
/*    std::string url;*/
/*    std::string response;*/
/*    long httpCode = 0;*/
/*};*/

// callback function for curl
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
  size_t totalSize = size * nmemb;
  output->append((char*)contents, totalSize);
  return totalSize;
}


Fuzzer::Fuzzer() {
  this->initVariables();
}


// assign wordlist file to vector
const std::vector<std::string> Fuzzer::getWordlist(std::string filePath) {
  std::vector<std::string> wordlist = {};
  std::ifstream wordlistFile(filePath);

  if (!wordlistFile) {
    std::cerr << "Error: Could not locate / open wordlist file." << std::endl;
    return {};
  }

  std::string line;
  while (std::getline(wordlistFile, line)) {
    wordlist.push_back(line);
  }
  wordlistFile.close();
  
  return wordlist;
}


// user input

// NOT IN USE
std::vector<std::string> Fuzzer::getUserWordlist() const {
  std::vector<std::string> wordlist;
  std::string line;

  while (std::getline(std::cin, line)) {
    wordlist.push_back(line);
  }
  
  return wordlist;
}

void Fuzzer::captureFlags(int argc, char* argv[]) {
  if (argc < 3) {
    std::cout << userInfo << std::endl;
    running = false;
    return;
  }

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    
    if (arg == "-u" && i + 1 < argc) {
      if (url.empty()) {
        url = argv[i + 1];
      }
      ++i; // skip the next argument
    } else if (arg == "-w" && i + 1 < argc) {
      if (wordlistPath.empty()) {
        wordlistPath = argv[i + 1];
      }
      ++i; // skip the next argument
    } else if (arg == "-v") {
      verbosity = true;
    } else if (arg == "-sD") {
      speed = "decrease";
    } else if (arg == "-sI") {
      speed = "increase";
    } else if (arg == "-bf") {
      fuzzing = "backupFile";
    } else {
      std::cerr << "Unrecognized flag: " << arg << std::endl;
      std::cout << "\n" << userInfo << std::endl;
      running = false;
      return;
    }
  } 
  
  if (url.empty()) {
    std::cout << userInfo << std::endl;
    running = false;
    return;
  }

  if (url.back() != '/') {
    url += '/';
  }
}

bool Fuzzer::validateURL(const std::string& url) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    std::cerr << "Error: Failed to initialize CURL." << std::endl;
    return false;
  }
  
  std::string dummyResponse;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &dummyResponse);
  /*curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullptr);*/
  
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    std::cerr << "Error: Failed to connect to the URL: "
              << url << "\n" << curl_easy_strerror(res) << std::endl;
    curl_easy_cleanup(curl);
    return false;
  }

  curl_easy_cleanup(curl);
  return true;
}


// FUZZING
void Fuzzer::defaultFuzzing() {
  std::vector<std::string> hits = {};
  std::vector<std::string> noResponse = {};
  std::string goodResponse = "";
  // wordlist
  std::vector<std::string> wordlist = getWordlist(wordlistPath);
  if (wordlist.empty()) {
    std::cerr << "Invalid wordlist file path.";
  }

  CURLM* multi_handle = curl_multi_init();
  std::map<CURL*, RequestData> requestMap;
  int still_running = 0;

  for (const auto& word : wordlist) {
    std::string currentUrl = url + word;

    CURL* curl = curl_easy_init();

    if (curl && multi_handle) {
      RequestData requestData;
      requestData.url = currentUrl;


      curl_easy_setopt(curl, CURLOPT_URL, currentUrl.c_str());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &requestData.response);
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

      if (verbosity) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      }
      
      if (speed == "decrease") {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
        curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, 50L);
      } else if (speed == "increase") {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, 100L);
      } else {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, 50L);
      }
      curl_multi_add_handle(multi_handle, curl);

      requestMap[curl] = requestData; // Track the CURL handle and its metadata
    }
  }

  // Perform the requests in parallel
  do {
    curl_multi_perform(multi_handle, &still_running);
    curl_multi_wait(multi_handle, nullptr, 0, 1000, nullptr);
  } while (still_running > 0);

  // Process results and cleanup
  for (auto& [curl, requestData] : requestMap) {
    curl_multi_remove_handle(multi_handle, curl);

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    requestData.httpCode = httpCode;

    if (httpCode == 200) {
      std::string output = ">> " + requestData.url + " ==> " + std::to_string(httpCode) + " <<";  
      hits.push_back(output);
      if (goodResponse.empty()) {
          goodResponse = requestData.response;
      }
      std::cout << "\n" << output << "\n" << std::endl;
    } else if (httpCode == 0) {
      noResponse.push_back(requestData.url);
      std::cerr << "No response received from URL: " << requestData.url << std::endl;
    } else {
      std::cout << "> " << requestData.url << " ==> " << httpCode << " <" << std::endl;
    }

    curl_easy_cleanup(curl);
  }

  curl_multi_cleanup(multi_handle);

  // Summary
  std::cout << "\nRequest Summary\n"
            << std::string(50, '=') << "\n"
            << "Requests: " << wordlist.size()
            << " | No Response: " << noResponse.size()
            << " | Successful: " << hits.size() 
            << "\n" << std::string(50, '=')
            << std::endl;
  
  std::cout << "Successful Requests:" << std::endl;
  for (const auto& req : hits) {
    std::cout << req << std::endl;
  }
  
  if (verbosity) {
    if (!goodResponse.empty()) {
      std::cout << "\nResponse Text:\n" << goodResponse << std::endl;
    }
    std::cout << "\nNo Response from:" << std::endl;
    for (const auto& res : noResponse) {
      std::cout << res << std::endl;
    }
  }
}

void Fuzzer::backupFileFuzzing() {
  std::vector<std::string> hits = {};
  std::vector<std::string> noResponse = {};
  std::string goodResponse = "";
  // wordlists
  std::vector<std::string> fileNames = getWordlist("data/fileNames.txt");
  std::vector<std::string> fileExtensions = getWordlist("data/fileExtensions.txt");
  if (fileNames.empty() || fileExtensions.empty()) {
    std::cerr << "One or both wordlists are empty." << std::endl;
    return;
  }
  
  CURLM* multi_handle = curl_multi_init();
  // map to track every CURL handle and its meta data
  std::map<CURL*, RequestData> requestMap;
  int still_running = 0;

  // Create CURL handles for all requests
  for (const auto& name : fileNames) {
    for (const auto& extension : fileExtensions) {
      std::string file = name + "." + extension;
      std::string currentUrl = url + file;

      CURL* curl = curl_easy_init();
      if (curl && multi_handle) {
        RequestData requestData;
        requestData.url = currentUrl;

        curl_easy_setopt(curl, CURLOPT_URL, currentUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &requestData.response);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        if (verbosity) {
          curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }
        
        if (speed == "decrease") {
          curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
          curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
          curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, 50L);
        } else if (speed == "increase") {
          curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
          curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
          curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, 100L);
        } else {
          curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
          curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
          curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, 50L);
        }
        curl_multi_add_handle(multi_handle, curl);

        /*curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);*/
        /*curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 5L);*/

        requestMap[curl] = requestData; // Track the CURL handle and its metadata
      }
    }
  }

  // Perform the requests in parallel
  do {
    curl_multi_perform(multi_handle, &still_running);
    curl_multi_wait(multi_handle, nullptr, 0, 1000, nullptr);
  } while (still_running > 0);

  // Process results and cleanup
  for (auto& [curl, requestData] : requestMap) {
    curl_multi_remove_handle(multi_handle, curl);

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    requestData.httpCode = httpCode;

    if (httpCode == 200) {
      std::string output = ">> " + requestData.url + " ==> " + std::to_string(httpCode) + " <<";  
      hits.push_back(output);
      if (goodResponse.empty()) {
          goodResponse = requestData.response;
      }
      std::cout << "\n" << output << "\n" << std::endl;
    } else if (httpCode == 0) {
      noResponse.push_back(requestData.url);
      std::cerr << "No response received from URL: " << requestData.url << std::endl;
    } else {
      std::cout << "> " << requestData.url << " ==> " << httpCode << " <" << std::endl;
    }

    curl_easy_cleanup(curl);
  }

  curl_multi_cleanup(multi_handle);

  // Summary
  int requestsAmount = fileNames.size() * fileExtensions.size();
  std::cout << "\nRequest Summary\n"
            << std::string(50, '=') << "\n"
            << "Requests: " << requestsAmount
            << " | No Response: " << noResponse.size()
            << " | Successful: " << hits.size() 
            << "\n" << std::string(50, '=')
            << std::endl;
  
  std::cout << "Successful Requests:" << std::endl;
  for (const auto& req : hits) {
    std::cout << req << std::endl;
  }
  
  if (verbosity) {
    if (!goodResponse.empty()) {
      std::cout << "\nResponse Text:\n" << goodResponse << std::endl;
    }
    std::cout << "\nNo Response from:" << std::endl;
    for (const auto& res : noResponse) {
      std::cout << res << std::endl;
    }
  }
}


void Fuzzer::run() {
  // validating url
  if (!validateURL(url)) {
    return;
  }

  while(running) {

    if (fuzzing == "backupFile") {
      backupFileFuzzing();
    } else {
      defaultFuzzing();
    }

    running = false;
  }
}
