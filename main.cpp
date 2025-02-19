#include "fuzzer.h"

int main(int argc, char* argv[]) {
 
  Fuzzer fuzzer;
  
  fuzzer.captureFlags(argc, argv);

  fuzzer.run();

  return 0;

}
