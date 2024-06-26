#include <iostream>

int main() {
  std::cout << "Hello World\n";
  std::cout << "";

  int* pointer = new int{10};
  delete pointer;

  return 0;
}