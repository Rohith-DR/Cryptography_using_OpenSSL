#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES = 10000;
static constexpr size_t HASH_SIZE_BYTES = 48;   // 384 bits for SHA-384
static constexpr size_t IV_SIZE_BYTES = 12;   // 96 bits for AES-GCM IV
static constexpr size_t GMAC_SIZE_BYTES = 16;   // 128 bits for AES-GCM authentication tag


bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	EVP_MD_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	size_t macLength = 0;

	// Create and initialize the context
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		goto err;
	}

	// Create a new key
	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keySizeBytes);
	if (pkey == NULL)
	{
		goto err;
	}

	// Initialize the DigestSign context with HMAC and SHA-256
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
	{
		goto err;
	}

	// Update the context with the message
	if (EVP_DigestSignUpdate(ctx, message, messageSizeBytes) != 1)
	{
		goto err;
	}

	// Finalize the DigestSign and retrieve the result length
	if (EVP_DigestSignFinal(ctx, NULL, &macLength) != 1)
	{
		goto err;
	}

	// Check if the provided buffer is large enough
	if (macLength > macBufferSizeBytes)
	{
		goto err;
	}

	// Retrieve the HMAC
	if (EVP_DigestSignFinal(ctx, macBuffer, &macLength) != 1)
	{
		goto err;
	}

	// Clean up and return success
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return true;

err:
	// Clean up and return failure
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return false;
}


#include <openssl/evp.h>
#include <cstdio>

bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	// Create a context for the HKDF operation
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;
	}

	// Initialize the context for key derivation
	if (EVP_PKEY_derive_init(pctx) <= 0)
	{
		printf("failed to initialize HKDF derive context\n");
		goto err;
	}

	// Set the HMAC digest algorithm to SHA-256
	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
	{
		printf("failed to set HKDF MD\n");
		goto err;
	}

	// Set the salt value
	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, static_cast<int>(saltSizeBytes)) <= 0)
	{
		printf("failed to set HKDF salt\n");
		goto err;
	}

	// Set the secret key material
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, static_cast<int>(secretMaterialSizeBytes)) <= 0)
	{
		printf("failed to set HKDF key\n");
		goto err;
	}

	// Set the context/application specific information
	if (context != NULL && contextSizeBytes > 0)
	{
		if (EVP_PKEY_CTX_add1_hkdf_info(pctx, context, static_cast<int>(contextSizeBytes)) <= 0)
		{
			printf("failed to set HKDF context\n");
			goto err;
		}
	}

	// Derive the key
	if (EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes) <= 0)
	{
		printf("failed to derive key\n");
		goto err;
	}

	// Successful derivation
	ret = true;

err:
	// Free the context
	EVP_PKEY_CTX_free(pctx);

	return ret;
}


size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

#include <openssl/evp.h>
#include <openssl/rand.h> // Include this for RAND_bytes
#include <cstring>
#include <cstdio>
#include <limits>

#define IV_SIZE_BYTES 12
#define GMAC_SIZE_BYTES 16
#define SYMMETRIC_KEY_SIZE_BYTES 32
#define MESSAGE_BUFFER_SIZE_BYTES 1024

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	if (plaintext == NULL || plaintextSizeBytes == 0)
	{
		printf("Invalid plaintext or size too small.\n");
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes < (plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		printf("Ciphertext buffer size is too small.\n");
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		printf("Failed to create EVP_CIPHER_CTX.\n");
		return false;
	}

	// Initialize encryption operation
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
	{
		printf("EVP_EncryptInit_ex failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Set IV length if default 12 bytes (96 bits) is not appropriate
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL) != 1)
	{
		printf("EVP_CIPHER_CTX_ctrl for IV length failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Generate a random IV
	if (!RAND_bytes(ciphertextBuffer, IV_SIZE_BYTES))
	{
		printf("RAND_bytes for IV failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Initialize key and IV
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, ciphertextBuffer) != 1)
	{
		printf("EVP_EncryptInit_ex for key and IV failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Provide AAD data if present
	if (aad && aadSizeBytes > 0)
	{
		int len;
		if (EVP_EncryptUpdate(ctx, NULL, &len, aad, static_cast<int>(aadSizeBytes)) != 1)
		{
			printf("EVP_EncryptUpdate for AAD failed.\n");
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
	}

	int len;
	int ciphertextLen = IV_SIZE_BYTES;
	// Provide the plaintext to be encrypted, and obtain the encrypted output
	if (EVP_EncryptUpdate(ctx, ciphertextBuffer + IV_SIZE_BYTES, &len, plaintext, static_cast<int>(plaintextSizeBytes)) != 1)
	{
		printf("EVP_EncryptUpdate for plaintext failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertextLen += len;

	// Finalize the encryption
	if (EVP_EncryptFinal_ex(ctx, ciphertextBuffer + ciphertextLen, &len) != 1)
	{
		printf("EVP_EncryptFinal_ex failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertextLen += len;

	// Get the tag
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, ciphertextBuffer + ciphertextLen) != 1)
	{
		printf("EVP_CIPHER_CTX_ctrl for getting tag failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertextLen += GMAC_SIZE_BYTES;

	if (pCiphertextSizeBytes != NULL)
	{
		*pCiphertextSizeBytes = ciphertextLen;
	}

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return true;
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		printf("Invalid ciphertext or size too small.\n");
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);

	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			printf("Invalid plaintext buffer.\n");
			return false;
		}
	}

	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		printf("Plaintext buffer size is too small.\n");
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		printf("Failed to create EVP_CIPHER_CTX.\n");
		return false;
	}

	// Initialize decryption operation
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
	{
		printf("EVP_DecryptInit_ex failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Set IV length if default 12 bytes (96 bits) is not appropriate
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL) != 1)
	{
		printf("EVP_CIPHER_CTX_ctrl for IV length failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Initialize key and IV
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, ciphertext) != 1)
	{
		printf("EVP_DecryptInit_ex for key and IV failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Provide AAD data if present
	if (aad && aadSizeBytes > 0)
	{
		int len;
		if (EVP_DecryptUpdate(ctx, NULL, &len, aad, static_cast<int>(aadSizeBytes)) != 1)
		{
			printf("EVP_DecryptUpdate for AAD failed.\n");
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
	}

	int len;
	int plaintextLen = 0;
	// Provide the ciphertext to be decrypted, and obtain the decrypted output
	if (EVP_DecryptUpdate(ctx, plaintextBuffer, &len, ciphertext + IV_SIZE_BYTES, static_cast<int>(ciphertextSizeBytes) - IV_SIZE_BYTES - GMAC_SIZE_BYTES) != 1)
	{
		printf("EVP_DecryptUpdate for ciphertext failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	plaintextLen = len;

	// Set expected tag value
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, (void*)(ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES)) != 1)
	{
		printf("EVP_CIPHER_CTX_ctrl for setting tag failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Finalize the decryption
	if (EVP_DecryptFinal_ex(ctx, plaintextBuffer + plaintextLen, &len) != 1)
	{
		printf("EVP_DecryptFinal_ex failed.\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	plaintextLen += len;

	if (pPlaintextSizeBytes != NULL)
	{
		*pPlaintextSizeBytes = plaintextLen;
	}

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return true;
}


bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT EVP_PKEY_CTX** pKeyContext)
{
	BIO* bio = BIO_new_file(keyFilename, "r"); 
	if (!bio) return false;

	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, (void*)filePassword); 
	BIO_free(bio);

	if (!pkey) return false;

	*pKeyContext = EVP_PKEY_CTX_new(pkey, NULL);
	if (!*pKeyContext) {
		EVP_PKEY_free(pkey);
		return false;
	}

	return true;
}

bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN EVP_PKEY_CTX* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (!mdctx) return false;

	if (EVP_DigestSignInit(mdctx, &privateKeyContext, EVP_sha256(), NULL, EVP_PKEY_CTX_get0_pkey(privateKeyContext)) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(privateKeyContext, RSA_PKCS1_PSS_PADDING) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	if (EVP_DigestSignUpdate(mdctx, message, messageSizeBytes) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	size_t siglen = signatureBufferSizeBytes;
	if (EVP_DigestSignFinal(mdctx, signatureBuffer, &siglen) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	EVP_MD_CTX_free(mdctx);
	return true;
}

bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN EVP_PKEY_CTX* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (!mdctx) return false;

	if (EVP_DigestVerifyInit(mdctx, &publicKeyContext, EVP_sha256(), NULL, EVP_PKEY_CTX_get0_pkey(publicKeyContext)) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(publicKeyContext, RSA_PKCS1_PSS_PADDING) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	if (EVP_DigestVerifyUpdate(mdctx, message, messageSizeBytes) <= 0) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}

	int verify = EVP_DigestVerifyFinal(mdctx, signature, signatureSizeBytes);
	*result = (verify == 1);

	EVP_MD_CTX_free(mdctx);
	return (verify == 1);
}


void CryptoWrapper::cleanKeyContext(INOUT EVP_PKEY_CTX** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN EVP_PKEY_CTX* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	if (!keyContext || !publicKeyPemBuffer) return false;

	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(keyContext);
	if (!pkey) return false;

	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio) return false;

	if (!PEM_write_bio_PUBKEY(bio, pkey)) {
		BIO_free(bio);
		return false;
	}

	BUF_MEM* bptr;
	BIO_get_mem_ptr(bio, &bptr);
	if (bptr->length > publicKeyBufferSizeBytes) {
		BIO_free(bio);
		return false;
	}

	memcpy(publicKeyPemBuffer, bptr->data, bptr->length);
	publicKeyPemBuffer[bptr->length] = '\0'; // Null-terminate the buffer

	BIO_free(bio);
	return true;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT EVP_PKEY_CTX* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	if (!context || !publicKeyPemBuffer) return false;

	BIO* bio = BIO_new_mem_buf(publicKeyPemBuffer, static_cast<int>(publicKeyBufferSizeBytes));
	if (!bio) return false;

	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (!pkey) return false;

	EVP_PKEY_CTX* newCtx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!newCtx) {
		EVP_PKEY_free(pkey);
		return false;
	}

	EVP_PKEY_CTX_free(context);
	context = newCtx;

	return true;
}

bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT EVP_PKEY_CTX** pPublicKeyContext)
{
	if (!certBuffer || !pPublicKeyContext) return false;

	BIO* bio = BIO_new_mem_buf(certBuffer, static_cast<int>(certSizeBytes));
	if (!bio) return false;

	X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (!cert) return false;

	EVP_PKEY* pkey = X509_get_pubkey(cert);
	X509_free(cert);

	if (!pkey) return false;

	*pPublicKeyContext = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);

	if (!*pPublicKeyContext) return false;

	return true;
}

bool CryptoWrapper::startDh(OUT EVP_PKEY** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	unsigned char generator = 2;
	EVP_PKEY_CTX* pctx = NULL;
	EVP_PKEY* params = NULL;
	EVP_PKEY* dhkey = NULL;
	BIO* bio = NULL;

	do {
		p = BN_get_rfc3526_prime_3072(NULL);
		if (p == NULL)
		{
			printf("Error: BN_get_rfc3526_prime_3072 failed\n");
			break;
		}

		g = BN_bin2bn(&generator, 1, NULL);
		if (g == NULL)
		{
			printf("Error: BN_bin2bn failed\n");
			break;
		}

		pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
		if (pctx == NULL)
		{
			printf("Error: EVP_PKEY_CTX_new_id failed\n");
			break;
		}

		if (EVP_PKEY_paramgen_init(pctx) <= 0)
		{
			printf("Error: EVP_PKEY_paramgen_init failed\n");
			break;
		}

		if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe3072) <= 0)
		{
			printf("Error: EVP_PKEY_CTX_set_dh_nid failed\n");
			break;
		}

		if (EVP_PKEY_paramgen(pctx, &params) <= 0)
		{
			printf("Error: EVP_PKEY_paramgen failed\n");
			break;
		}

		pctx = EVP_PKEY_CTX_new(params, NULL);
		if (pctx == NULL)
		{
			printf("Error: EVP_PKEY_CTX_new failed\n");
			break;
		}

		if (EVP_PKEY_keygen_init(pctx) <= 0)
		{
			printf("Error: EVP_PKEY_keygen_init failed\n");
			break;
		}

		if (EVP_PKEY_keygen(pctx, &dhkey) <= 0)
		{
			printf("Error: EVP_PKEY_keygen failed\n");
			break;
		}

		*pDhContext = dhkey;

		// Extract the public key
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
		{
			printf("Error: BIO_new failed\n");
			break;
		}

		if (PEM_write_bio_PUBKEY(bio, dhkey) <= 0)
		{
			printf("Error: PEM_write_bio_PUBKEY failed\n");
			break;
		}

		int pubKeyLen = BIO_pending(bio);
		if (pubKeyLen > publicKeyBufferSizeBytes)
		{
			printf("Error: Public key buffer size is too small. Required size: %d\n", pubKeyLen);
			break;
		}

		BIO_read(bio, publicKeyBuffer, pubKeyLen);
		ret = true;
	} while (0);

	BN_free(p);
	BN_free(g);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(params);
	BIO_free(bio);

	return ret;
}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{
	BIO* bio = BIO_new_mem_buf(peerPublicKey, static_cast<int>(peerPublicKeySizeBytes));
	if (bio == NULL)
	{
		return false;
	}

	*genPeerPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	return (*genPeerPublicKey != NULL);
}

bool CryptoWrapper::getDhSharedSecret(INOUT EVP_PKEY* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;
	size_t secretLen;

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
	{
		goto err;
	}

	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey))
	{
		goto err;
	}

	derivationCtx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (derivationCtx == NULL)
	{
		goto err;
	}

	if (EVP_PKEY_derive_init(derivationCtx) <= 0)
	{
		goto err;
	}

	if (EVP_PKEY_derive_set_peer(derivationCtx, genPeerPublicKey) <= 0)
	{
		goto err;
	}

	if (EVP_PKEY_derive(derivationCtx, NULL, &secretLen) <= 0)
	{
		goto err;
	}

	if (secretLen > sharedSecretBufferSizeBytes)
	{
		goto err;
	}

	if (EVP_PKEY_derive(derivationCtx, sharedSecretBuffer, &secretLen) <= 0)
	{
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_free(genPeerPublicKey);
	EVP_PKEY_CTX_free(derivationCtx);

	return ret;
}

void CryptoWrapper::cleanDhContext(INOUT EVP_PKEY** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;
	X509_STORE* store = NULL;
	X509_STORE_CTX* ctx = NULL;
	char cn[256] = { 0 };

	do {
		caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
		if (caCert == NULL)
		{
			break;
		}

		userCert = loadCertificate(certBuffer, certSizeBytes);
		if (userCert == NULL)
		{
			break;
		}

		store = X509_STORE_new();
		if (store == NULL)
		{
			break;
		}

		if (X509_STORE_add_cert(store, caCert) != 1)
		{
			break;
		}

		ctx = X509_STORE_CTX_new();
		if (ctx == NULL)
		{
			break;
		}

		if (X509_STORE_CTX_init(ctx, store, userCert, NULL) != 1)
		{
			break;
		}

		if (X509_verify_cert(ctx) != 1)
		{
			break;
		}

		// Extract CN from the certificate
		X509_NAME* subjectName = X509_get_subject_name(userCert);
		if (subjectName == NULL)
		{
			break;
		}

		if (X509_NAME_get_text_by_NID(subjectName, NID_commonName, cn, sizeof(cn)) <= 0)
		{
			break;
		}

		// Directly compare the CN
		if (strcmp(cn, expectedCN) != 0)
		{
			break;
		}

		ret = 1; // Success
	} while (0);

	X509_free(caCert);
	X509_free(userCert);
	X509_STORE_free(store);
	X509_STORE_CTX_free(ctx);

	return ret;
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
