#include <iostream>
#include <string.h>

std::string xorCipher(std::string str_in, std::string key) {
   std::string str_out;
   int idx;

   for (int i = 0; i < str_in.length(); i++) {
      idx = i % key.length();
      str_out.push_back(str_in[i] ^ key[idx]);
   }

   return str_out;
}

int main(int argc, char* argv[]) {

   std::string key = "Key123";
   std::string msg = "Test message";

   printf("Encrypting: \"%s\"\n", msg.c_str());
   printf("KEY: \"%s\"\n", key.c_str());

   // Printing in hex since chars not usually in ASCII range
   std::string encrypted = xorCipher(msg, key);
   printf("Encrypted message: \"%x\"\n", encrypted.c_str());

   std::string decrypted = xorCipher(encrypted, key);
   printf("Decrypted message: \"%s\"\n", decrypted.c_str());

   return 0;
}