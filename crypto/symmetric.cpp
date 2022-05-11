#include "http.h"

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
   std::string outData = "";

   std::string key = "Key123";
   std::string msg = "Test message";

   // printf("Encrypting: \"%s\"\n", msg.c_str());
   outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'symmetric.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Encrypting: ";
   outData.append(msg.c_str());
   outData.append(".\'}");
   makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

   // printf("KEY: \"%s\"\n", key.c_str());
   outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'symmetric.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Key: ";
   outData.append(key.c_str());
   outData.append(".\'}");
   makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

   // Printing in hex since chars not usually in ASCII range
   std::string encrypted = xorCipher(msg, key);
   //printf("Encrypted message: \"%x\"\n", encrypted.c_str());
   outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'symmetric.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Encrypted message: ";
   outData.append(encrypted.c_str());
   outData.append(".\'}");

   std::string decrypted = xorCipher(encrypted, key);
   //printf("Decrypted message: \"%s\"\n", decrypted.c_str());
   outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'symmetric.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Encrypted message: ";
   outData.append(decrypted.c_str());
   outData.append(".\'}");

   return 0;
}