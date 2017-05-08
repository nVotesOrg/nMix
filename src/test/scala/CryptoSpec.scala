package org.nvotes.trustee

import java.nio.file.Paths

import org.scalatest.FlatSpec
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Tests the Crypto object functionality
 *
 *  Basic tests for RSA signing, verifying and AES encryption/decryption
 */
class CryptoSpec extends FlatSpec {

  "ok signature" should "verify ok" in {
    val content = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)
    val privateKey = Crypto.readPrivateRsa(Paths.get(getClass.getResource("/rsa_test.pem").toURI))
    val publicKey = Crypto.readPublicRsa(Paths.get(getClass.getResource("/rsa_test.pub.pem").toURI))
    val signature = Crypto.sign(content, privateKey)
    val verified = Crypto.verify(content, signature, publicKey)

    assert(verified)
  }

  "bad signature" should "not verify" in {
    val content = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)
    val privateKey = Crypto.readPrivateRsa(Paths.get(getClass.getResource("/rsa_test.pem").toURI))
    val publicKey = Crypto.readPublicRsa(Paths.get(getClass.getResource("/rsa_test.pub.pem").toURI))
    val signature = Crypto.sign(content, privateKey)

    val content2 = "mismatch".getBytes(StandardCharsets.UTF_8)
    val verified = Crypto.verify(content2, signature, publicKey)

    assert(!verified)
  }

  "encryption" should "decrypt ok" in {
    val content = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)
    val key = Crypto.readAESKey(Paths.get(getClass.getResource("/test_aes.ucs").toURI))
    val encrypted = Crypto.encryptAES(content, key)
    val decrypted = Crypto.decryptAES(encrypted, key)

    assert(decrypted.sameElements(content))
  }

  "decryption with wrong key" should "fail" in {
    val content = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)
    val key = Crypto.readAESKey(Paths.get(getClass.getResource("/test_aes.ucs").toURI))
    val encrypted = Crypto.encryptAES(content, key)

    val wrongKey = Crypto.randomAESKeyElement

    assertThrows[IllegalArgumentException] {
      val decrypted = Crypto.decryptAES(encrypted, wrongKey)
      // just in case there is no error in the unpadding
      if(!decrypted.sameElements(content)) {
        throw new IllegalArgumentException
      }
    }
  }

  "encryption (str)" should "decrypt ok" in {
    val content = UUID.randomUUID().toString()
    val key = Crypto.readAESKey(Paths.get(getClass.getResource("/test_aes.ucs").toURI))
    val encrypted = Crypto.encryptAES(content, key)
    val decrypted = Crypto.decryptAES(encrypted, key)

    assert(decrypted == content)
  }

  "decryption (str) with wrong key" should "fail" in {
    val content = UUID.randomUUID().toString()
    val key = Crypto.readAESKey(Paths.get(getClass.getResource("/test_aes.ucs").toURI))
    val encrypted = Crypto.encryptAES(content, key)

    val wrongKey = Crypto.randomAESKeyElement

    assertThrows[IllegalArgumentException] {
      val decrypted = Crypto.decryptAES(encrypted, wrongKey)
      // just in case there is no error in the unpadding
      if(decrypted != content) {
        throw new IllegalArgumentException
      }
    }
  }

  "encryption (str) with bin key" should "decrypt ok" in {
    val content = UUID.randomUUID().toString()
    val key = Crypto.readAESKeyBytes(Paths.get(getClass.getResource("/test_aes.bin").toURI))
    val encrypted = Crypto.encryptAES(content, key)
    val decrypted = Crypto.decryptAES(encrypted, key)

    assert(decrypted == content)
  }
}