#include "aes_gcm.h"

AESGCM:: ~AESGCM(){
    Cleanup();
}

// Freebie: initialize AES class
AESGCM::AESGCM( BYTE key[AES_256_KEY_SIZE]){
    hAlg = 0;
    hKey = NULL;

    // create a handle to an AES-GCM provider
    nStatus = ::BCryptOpenAlgorithmProvider(
        &hAlg, 
        BCRYPT_AES_ALGORITHM, 
        NULL, 
        0);
    if (! NT_SUCCESS(nStatus))
    {
        // printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", nStatus);
        Cleanup();
        return;
    }
    if (!hAlg){
        // printf("Invalid handle!\n");
    }
    nStatus = ::BCryptSetProperty(
        hAlg, 
        BCRYPT_CHAINING_MODE, 
        (BYTE*)BCRYPT_CHAIN_MODE_GCM, 
        sizeof(BCRYPT_CHAIN_MODE_GCM), 
        0);
    if (!NT_SUCCESS(nStatus)){
         // printf("**** Error 0x%x returned by BCryptGetProperty ><\n", nStatus);
         Cleanup();
         return;
    }
  
    nStatus = ::BCryptGenerateSymmetricKey(
        hAlg, 
        &hKey, 
        NULL, 
        0, 
        key, 
        AES_256_KEY_SIZE, 
        0);
    if (!NT_SUCCESS(nStatus)){
        // printf("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", nStatus);
        Cleanup();
        return;
    }
    DWORD cbResult = 0;
     nStatus = ::BCryptGetProperty(
         hAlg, 
         BCRYPT_AUTH_TAG_LENGTH, 
         (BYTE*)&authTagLengths, 
         sizeof(authTagLengths), 
         &cbResult, 
         0);
   if (!NT_SUCCESS(nStatus)){
       // printf("**** Error 0x%x returned by BCryptGetProperty when calculating auth tag len\n", nStatus);
   }
}

void AESGCM::Decrypt(BYTE* nonce, size_t nonceLen, BYTE* data, size_t dataLen, BYTE* macTag, size_t macTagLen){
    // nonce is textIV
    // nonceLen is textIV length
    // data is message
    // dataLen is message length
    // macTag is pointer to message authentication code
    // macTagLen is box->authTagLengths.dwMinLength from BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths

    // printf("In the decrypt function...\n");
    // Need size for plaintext
    ULONG confirmSize;

    // Add message auth code info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO decryptInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(decryptInfo);
    decryptInfo.pbMacContext = macTag;
    decryptInfo.cbMacContext = macTagLen;

    nStatus = BCryptDecrypt( 
        hKey,
        (PUCHAR) data, //UCHAR is an unsigned char, PUCHAR is a pointer to an unsigned char
        dataLen,
        &decryptInfo,
        (PUCHAR) nonce,
        nonceLen,
        NULL,
        0,
        &confirmSize, //Not necessary now
        BCRYPT_PAD_NONE
    );

    if (!NT_SUCCESS(nStatus))
    {
        // printf("**** Error 0x%x returned by BCryptDecrypt (getting size)\n", nStatus);
        Cleanup();
        return;
    }


    // printf("confirmSize: ");
    // printf("%lu\n", confirmSize);

    nStatus = BCryptDecrypt( 
        hKey,
        (PUCHAR) data, //UCHAR is an unsigned char, PUCHAR is a pointer to an unsigned char
        dataLen,
        &decryptInfo,
        (PUCHAR) nonce,
        nonceLen,
        (PUCHAR) plaintext,
        confirmSize,
        &confirmSize, //Not necessary now
        BCRYPT_PAD_NONE
    );

    if (!NT_SUCCESS(nStatus))
    {
        // printf("**** Error 0x%x returned by BCryptDecrypt (decrypting data)\n", nStatus);
        Cleanup();
        return;
    }

    // printf("plaintext: ");
    // printf("%s\n", &plaintext);
}

void AESGCM::Encrypt(BYTE* nonce, size_t nonceLen, BYTE* data, size_t dataLen){
    // nonce is textIV
    // nonceLen is textIV length
    // data is message
    // dataLen is message length

    // Need size required for ciphertext
    ptBufferSize = dataLen;
    ULONG confirmSize;

    nStatus = BCryptEncrypt( 
        hKey,
        (PUCHAR) data, //UCHAR is an unsigned char, PUCHAR is a pointer to an unsigned char
        dataLen,
        NULL, //?
        (PUCHAR) nonce,
        nonceLen,
        NULL,
        0,
        &confirmSize, //Receive size in bytes required for ciphertext
        BCRYPT_PAD_NONE
    );

    if (!NT_SUCCESS(nStatus))
    {
        // printf("**** Error 0x%x returned by BCryptEncrypt (getting size)\n", nStatus);
        Cleanup();
        return;
    }

    // printf("confirmSize: ");
    // printf("%lu\n", confirmSize);

    // With size, can encrypt
    nStatus = BCryptEncrypt( 
        hKey,
        (PUCHAR) data, //UCHAR is an unsigned char, PUCHAR is a pointer to an unsigned char
        dataLen,
        NULL, //?
        (PUCHAR) nonce,
        nonceLen,
        (PUCHAR) ciphertext, //Receive ciphertext, data method of class AESGCM
        confirmSize,
        &confirmSize, //Not necessary now
        BCRYPT_PAD_NONE
    );

    //ptBufferSize = confirmSize;

    if (!NT_SUCCESS(nStatus))
    {
        // printf("**** Error 0x%x returned by BCryptEncrypt (encrypting data)\n", nStatus);
        Cleanup();
        return;
    }

    // printf("ciphertext: ");
    // printf("%s\n", &ciphertext);
}

void AESGCM::Cleanup(){
    if(hAlg){
        ::BCryptCloseAlgorithmProvider(hAlg,0);
        hAlg = NULL;
    }
    if(hKey){
        ::BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if(tag){
          ::HeapFree(GetProcessHeap(), 0, tag);
          tag = NULL;
    }
    if(ciphertext){
        ::HeapFree(GetProcessHeap(), 0, tag);
        ciphertext = NULL;
    }
    if(plaintext){
        ::HeapFree(GetProcessHeap(), 0, plaintext);
        plaintext = NULL;
    }
}