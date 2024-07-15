#include <list>
#include <stdio.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


static constexpr size_t MAX_CONTEXT_SIZE = 100;


Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
            _state = GOODBYE_SESSION_MESSAGE;
        }
    }
}

void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            // we better clean it using some Utils function
            Utils::secureCleanMemory(reinterpret_cast<BYTE*>(_privateKeyPassword), strlen(_privateKeyPassword));
            delete[] _privateKeyPassword;
            _privateKeyPassword = NULL;
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}


bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}


void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort) 
{
        memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
        _remoteAddress.sin_family = AF_INET;
        _remoteAddress.sin_port = htons(remotePort);
        _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}


void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter =_outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}


bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }

    return result;
}


void Session::cleanDhData()
{
    if (_dhContext != NULL)
    {
        EVP_PKEY_free(_dhContext); // Use OpenSSL's function to free the EVP_PKEY
        _dhContext = NULL;
    }

    Utils::secureCleanMemory(_localDhPublicKeyBuffer, sizeof(_localDhPublicKeyBuffer));
    Utils::secureCleanMemory(_remoteDhPublicKeyBuffer, sizeof(_remoteDhPublicKeyBuffer));
    Utils::secureCleanMemory(_sharedDhSecretBuffer, sizeof(_sharedDhSecretBuffer));
}

void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    size_t mackeysizebytes = 0;
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        exit(0);
    }

    // Assuming _sessionKey is already initialized and contains the secret material
    BYTE salt[48] = { 0 }; // Use 48 bytes for the salt

    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
        salt, sizeof(salt),
        _sessionKey, sizeof(_sessionKey),
        reinterpret_cast<const BYTE*>(keyDerivationContext), strlen(keyDerivationContext),
        macKeyBuffer, mackeysizebytes))
    {
        // Handle error
        exit(0);
    }
}

void Session::deriveSessionKey()
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        exit(0);
    }

    // Assuming _sharedDhSecretBuffer contains the shared secret from the DH key exchange
    BYTE salt[48] = { 0 }; // Use 48 bytes for the salt

    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
        salt, sizeof(salt),
        _sharedDhSecretBuffer, sizeof(_sharedDhSecretBuffer),
        reinterpret_cast<const BYTE*>(keyDerivationContext), strlen(keyDerivationContext),
        _sessionKey, sizeof(_sessionKey)))
    {
        // Handle error
        exit(0);
    }
}

ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    // we will be building the following message parts:
    // 1: my DH public key 
    // 2: My certificate (PEM)
    // 3: Signature over concatenated public keys with my permanent private key
    // 4: MAC over my certificate with the shared MAC key

    // get my certificate
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("prepareDhMessage - Error reading certificate filename - %s\n", _localCertFilename);
        return NULL;
    }

    // get my private key for signing
    EVP_PKEY_CTX* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("prepareDhMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
        cleanDhData();
        return NULL;
    }

    ByteSmartPtr concatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareDhMessage #%d failed - Error concatenating public keys\n", messageType);
        cleanDhData();
        return NULL;
    }

    BYTE signature[SIGNATURE_SIZE_BYTES];
    size_t signatureSize = SIGNATURE_SIZE_BYTES;
    if (!CryptoWrapper::signMessageRsa3072Pss(concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(), privateKeyContext, signature, signatureSize))
    {
        printf("prepareDhMessage #%d failed - Error signing concatenated public keys\n", messageType);
        cleanDhData();
        return NULL;
    }

    // Now we will calculate the MAC over my certificate
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(_sessionKey, sizeof(_sessionKey), (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("prepareDhMessage #%d failed - Error calculating MAC over certificate\n", messageType);
        cleanDhData();
        return NULL;
    }

    // pack all of the parts together
    ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), signature, SIGNATURE_SIZE_BYTES, calculatedMac, HMAC_SIZE_BYTES);
    Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);
    return messageToSend;
}

bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    unsigned int expectedNumberOfParts = 4;
    unsigned int partIndex = 0;

    // We are expecting 4 parts
    // 1: Remote public DH key (in message type 3 we will check that it equals the value received in message type 1)
    // 2: Remote certificate (PEM) null terminated
    // 3: Signature over concatenated public keys (remote|local)
    // 4: MAC over remote certificate with the shared MAC key

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
        return false;
    }

    // Extract parts
    const BYTE* remoteDhPublicKey = parts[partIndex++].part;
    const BYTE* remoteCert = parts[partIndex++].part;
    const BYTE* signature = parts[partIndex++].part;
    const BYTE* receivedMac = parts[partIndex++].part;

    // Verify the remote certificate
    EVP_PKEY_CTX* remotePublicKeyContext = NULL;
    if (!CryptoWrapper::getPublicKeyFromCertificate(remoteCert, strlen((const char*)remoteCert), &remotePublicKeyContext))
    {
        printf("verifySigmaMessage #%d failed - Error extracting public key from certificate\n", messageType);
        return false;
    }

    if (!CryptoWrapper::checkCertificate((const BYTE*)_rootCaCertFilename, strlen(_rootCaCertFilename), remoteCert, strlen((const char*)remoteCert), _expectedRemoteIdentityString))
    {
        printf("verifySigmaMessage #%d failed - Certificate verification failed\n", messageType);
        return false;
    }

    // Verify the signature over the concatenated public keys
    ByteSmartPtr concatenatedPublicKeysSmartPtr = concat(2, remoteDhPublicKey, DH_KEY_SIZE_BYTES, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("verifySigmaMessage #%d failed - Error concatenating public keys\n", messageType);
        return false;
    }

    bool signatureValid = false;
    if (!CryptoWrapper::verifyMessageRsa3072Pss(concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(), remotePublicKeyContext, signature, SIGNATURE_SIZE_BYTES, &signatureValid) || !signatureValid)
    {
        printf("verifySigmaMessage #%d failed - Signature verification failed\n", messageType);
        return false;
    }

    if (messageType == 2)
    {
        // Calculate the shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, remoteDhPublicKey, DH_KEY_SIZE_BYTES, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("verifySigmaMessage #%d failed - Error calculating shared secret\n", messageType);
            return false;
        }
    }

    // Verify the MAC over the certificate
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(_sessionKey, sizeof(_sessionKey), remoteCert, strlen((const char*)remoteCert), calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("verifySigmaMessage #%d failed - Error calculating MAC over certificate\n", messageType);
        return false;
    }

    if (memcmp(calculatedMac, receivedMac, HMAC_SIZE_BYTES) != 0)
    {
        printf("verifySigmaMessage #%d failed - MAC verification failed\n", messageType);
        return false;
    }

    return true;
}

ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
{
    size_t ciphertextBufferSize = CryptoWrapper::getCiphertextSizeAES_GCM256(messageSize);
    BYTE* ciphertextBuffer = (BYTE*)Utils::allocateBuffer(ciphertextBufferSize);
    if (ciphertextBuffer == NULL)
    {
        return NULL;
    }

    size_t ciphertextSize = 0;
    if (!CryptoWrapper::encryptAES_GCM256(
        _sessionKey, SYMMETRIC_KEY_SIZE_BYTES, // key
        message, messageSize,                  // plaintext
        (const BYTE*)(&messageSize), sizeof(messageSize), // aad
        ciphertextBuffer, ciphertextBufferSize, &ciphertextSize)) // ciphertext buffer - output
    {
        printf("Error during encryptAES_GCM256!\n");
        Utils::secureCleanMemory(ciphertextBuffer, ciphertextBufferSize);
        Utils::freeBuffer(ciphertextBuffer);
        return NULL;
    }

    ByteSmartPtr result(ciphertextBuffer, ciphertextSize);
    return result;
}


bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{
    size_t ciphertextSize = header->payloadSize;
    size_t plaintextBufferSize = CryptoWrapper::getPlaintextSizeAES_GCM256(ciphertextSize);
    BYTE* plaintextBuffer = (BYTE*)Utils::allocateBuffer(plaintextBufferSize);
    if (plaintextBuffer == NULL)
    {
        return false;
    }

    size_t plaintextSize = 0;
    if (!CryptoWrapper::decryptAES_GCM256(
        _sessionKey, SYMMETRIC_KEY_SIZE_BYTES, // key
        buffer, ciphertextSize,                // ciphertext
        (const BYTE*)(&plaintextBufferSize), sizeof(plaintextBufferSize), // aad - must use the same AAD
        plaintextBuffer, plaintextBufferSize, &plaintextSize)) // plaintextBuffer - output
    {
        printf("Error during decryptAES_GCM256!\n");
        Utils::secureCleanMemory(plaintextBuffer, plaintextBufferSize);
        Utils::freeBuffer(plaintextBuffer);
        return false;
    }

    memcpy_s(buffer, plaintextBufferSize, plaintextBuffer, plaintextSize);
    Utils::secureCleanMemory(plaintextBuffer, plaintextBufferSize);
    Utils::freeBuffer(plaintextBuffer);

    if (pPlaintextSize != NULL)
    {
        *pPlaintextSize = plaintextSize;
    }

    return true;
}

bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}


ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by the smart pointer logic)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by caller's smart pointer)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t* partSize = (size_t*)(buffer + pos);
        pos += sizeof(size_t);
        if (*partSize == 0 || (pos + *partSize) > bufferSize)
            return false;

        MessagePart messagePart;
        messagePart.partSize = *partSize;
        messagePart.part = (buffer + pos);
        partsList.push_back(messagePart);
        pos += *partSize;
    }

    result.resize(partsList.size());
    unsigned int i = 0;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        result[i].part = it->part;
        result[i].partSize = it->partSize;
        i++;
    }
    return true;
}















