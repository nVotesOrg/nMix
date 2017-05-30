/**
 * This file is part of nMix.
 * Copyright (C) 2015-2016-2017  Agora Voting SL <agora@agoravoting.com>

 * nMix is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * nMix is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with nMix.  If not, see <http://www.gnu.org/licenses/>.
**/

package org.nvotes.mix

import java.security._
import java.io.BufferedInputStream
import javax.xml.bind.DatatypeConverter
import java.nio.file.Paths
import java.nio.file.Path
import java.nio.file.Files
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.io.InputStream
import java.util.Base64

import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZMod
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement
import ch.bfh.unicrypt.helper.converter.classes.ConvertMethod
import ch.bfh.unicrypt.helper.converter.classes.bytearray.BigIntegerToByteArray
import ch.bfh.unicrypt.helper.converter.classes.bytearray.StringToByteArray
import ch.bfh.unicrypt.helper.hash.HashAlgorithm
import ch.bfh.unicrypt.helper.hash.HashMethod
import ch.bfh.unicrypt.helper.math.Alphabet
import ch.bfh.unicrypt.math.algebra.concatenative.classes.ByteArrayMonoid
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringMonoid
import ch.bfh.unicrypt.crypto.schemes.signature.classes.RSASignatureScheme
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.RSAEncryptionScheme
import ch.bfh.unicrypt.crypto.schemes.padding.classes.PKCSPaddingScheme
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.AESEncryptionScheme
import ch.bfh.unicrypt.crypto.schemes.padding.classes.ANSIPaddingScheme
import ch.bfh.unicrypt.crypto.schemes.padding.classes.PKCSPaddingScheme
import ch.bfh.unicrypt.math.algebra.general.classes.FiniteByteArrayElement
import ch.bfh.unicrypt.math.algebra.concatenative.classes.ByteArrayElement
import ch.bfh.unicrypt.helper.array.classes.ByteArray
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.math.algebra.general.classes.Pair

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.ByteOrder

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import org.nvotes.libmix._

/** Provides various cryptographic operations */
object Crypto {

  /** These unicrypt settings must be common to sign generating and verifying methods */
  val HASH_METHOD = HashMethod.getInstance(HashAlgorithm.SHA256)
  val CONVERT_METHOD = ConvertMethod.getInstance(BigIntegerToByteArray.getInstance(ByteOrder.BIG_ENDIAN),
      StringToByteArray.getInstance(StandardCharsets.UTF_8))

  /** It is unclear at this time whether there are benefits to using keylengths of 256 */
  val AES_KEY_LENGTH = AESEncryptionScheme.KeyLength.KEY128
  val AES_MODE = AESEncryptionScheme.Mode.CBC
  val IV_SIZE = AESEncryptionScheme.AES_BLOCK_SIZE / 8
  val PADDING_SIZE = AESEncryptionScheme.AES_BLOCK_SIZE / 8

  /** Hash function for standalone hashing (outside of unicrypt) */
  val HASH_FUNCTION = "SHA-512"

  /** All hashes use the hash function specified here */
  def getMessageDigest() = MessageDigest.getInstance(HASH_FUNCTION)

  /** Returns the sha512 hash of the given String as a String */
  def hash(input: String): String = {
    val hash = getMessageDigest()
    val in = new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8))
    val din = new DigestInputStream(in, hash)
    while (din.read() != -1){}
    din.close()

    DatatypeConverter.printHexBinary(hash.digest())
  }

  /** The following methods return hashes for objects
   *  that are too large to be hashed as one entire String.
   *  They are hashed using newline characters as field separators
   *  so that they match the implementation of the HashingWriter
   *  and HashingReader in IO.scala.
   */

  /** Returns the sha512 hash of the Plaintexts object as a String */
  def hash(input: Plaintexts): String = {
    val hash = getMessageDigest()
    input.plaintexts.foreach { p =>
      val next = p + HashingWriter.NEWLINE
      hash.update(next.getBytes(StandardCharsets.UTF_8))
    }
    val end = HashingWriter.NEWLINE
    hash.update(end.getBytes(StandardCharsets.UTF_8))

    DatatypeConverter.printHexBinary(hash.digest())
  }

  /** Returns the sha512 hash of a sequence of PartialDecryptionDTO's as a String */
  def hash(input: Seq[PartialDecryptionDTO]): String = {
    val hash = getMessageDigest()
    input.map(Crypto.hash).foreach { h =>
      hash.update(h.getBytes(StandardCharsets.UTF_8))
    }

    DatatypeConverter.printHexBinary(hash.digest())
  }

  /** Returns the sha512 hash of the PartialDecryptionDTO object as a String */
  def hash(input: PartialDecryptionDTO): String = {
    val hash = getMessageDigest()
    var next = input.proofDTO.commitment + HashingWriter.NEWLINE
    hash.update(next.getBytes(StandardCharsets.UTF_8))
    next = input.proofDTO.challenge + HashingWriter.NEWLINE
    hash.update(next.getBytes(StandardCharsets.UTF_8))
    next = input.proofDTO.response + HashingWriter.NEWLINE
    hash.update(next.getBytes(StandardCharsets.UTF_8))

    input.partialDecryptions.foreach { p =>
      next = p + HashingWriter.NEWLINE
      hash.update(next.getBytes(StandardCharsets.UTF_8))
    }
    val end = HashingWriter.NEWLINE
    hash.update(end.getBytes(StandardCharsets.UTF_8))

    DatatypeConverter.printHexBinary(hash.digest())
  }

  /** Returns a RSA signature of the given String as a byte array */
  def sign(content: String, privateKey: RSAPrivateKey): Array[Byte] = {
    val toSign = content.getBytes(StandardCharsets.UTF_8)
    sign(toSign, privateKey)
  }

  /** Returns a RSA signature of the given byte array as a byte array */
  def sign(content: Array[Byte], privateKey: RSAPrivateKey): Array[Byte] = {
    val byteSpace = ByteArrayMonoid.getInstance()
    val toSign = byteSpace.getElement(content)
    val scheme = RSASignatureScheme.getInstance(toSign.getSet(),
      ZMod.getInstance(privateKey.getModulus()), CONVERT_METHOD, HASH_METHOD)
    val privateKeyElement = scheme.getVerificationKeySpace().getElement(privateKey.getPrivateExponent())

    scheme.sign(privateKeyElement, toSign).convertToByteArray.getBytes
  }

  /** Returns true if the given signature byte array and content String is correct */
  def verify(content: String, signature: Array[Byte], publicKey: RSAPublicKey): Boolean = {
    val signed = content.getBytes(StandardCharsets.UTF_8)
    verify(signed, signature, publicKey)
  }

  /** Returns true if the given signature String and content String is correct */
  def verify(content: String, signature: String, publicKey: RSAPublicKey): Boolean = {
    val signed = content.getBytes(StandardCharsets.UTF_8)
    val sig = signature.getBytes(StandardCharsets.UTF_8)

    verify(signed, sig, publicKey)
  }

  /** Returns true if the given signature byte array and content byte array is correct */
  def verify(content: Array[Byte], signature: Array[Byte], publicKey: RSAPublicKey): Boolean = {
    val byteSpace = ByteArrayMonoid.getInstance()
    val signed = byteSpace.getElement(content)
    val scheme = RSASignatureScheme.getInstance(signed.getSet(),
      ZMod.getInstance(publicKey.getModulus()), CONVERT_METHOD, HASH_METHOD)
    val signatureByteArray = ByteArray.getInstance(signature :_*)
    val signatureElement = scheme.getSignatureSpace.getElementFrom(signatureByteArray)
    val publicKeyElement = scheme.getSignatureKeySpace().getElement(publicKey.getPublicExponent())

    scheme.verify(publicKeyElement, signed, signatureElement).isTrue
  }

  /** Returns the AES encryption of the given byte array as a byte array */
  def encryptAES(content: Array[Byte], key: FiniteByteArrayElement): (Array[Byte], Array[Byte]) = {
    val byteSpace = ByteArrayMonoid.getInstance()
    val toEncrypt = byteSpace.getElement(content)
    val pkcs = PKCSPaddingScheme.getInstance(PADDING_SIZE)
    val paddedMessage = pkcs.pad(toEncrypt)
    val iv = ByteArray.getRandomInstance(IV_SIZE)
    val aes = AESEncryptionScheme.getInstance(AES_KEY_LENGTH, AES_MODE, iv)
    val encryptedMessage = aes.encrypt(key, paddedMessage)

    val encrypted = encryptedMessage.convertToByteArray.getBytes
    (encrypted, iv.getBytes)
  }

  /** Returns the AES decryption of the given String as a byte array */
  def decryptAES(content: Array[Byte], key: FiniteByteArrayElement, iv: Array[Byte]): Array[Byte] = {
    val byteSpace = ByteArrayMonoid.getInstance()
    val toDecrypt = byteSpace.getElement(content)
    val ivBytes = ByteArray.getInstance(iv :_*)
    val aes = AESEncryptionScheme.getInstance(AES_KEY_LENGTH, AES_MODE, ivBytes)
    val decryptedMessage = aes.decrypt(key, toDecrypt)
    val pkcs = PKCSPaddingScheme.getInstance(PADDING_SIZE)
    val unpaddedMessage = pkcs.unpad(decryptedMessage)

    unpaddedMessage.convertToByteArray.getBytes
  }

  /** Returns the AES encryption of the given String as a base64 encoded String */
  def encryptAES(content: String, key: FiniteByteArrayElement): (String, String) = {
    val byteSpace = ByteArrayMonoid.getInstance()
    val toEncrypt = byteSpace.getElement(content.getBytes(StandardCharsets.UTF_8))
    val pkcs = PKCSPaddingScheme.getInstance(PADDING_SIZE)
    val paddedMessage = pkcs.pad(toEncrypt)
    val iv = ByteArray.getRandomInstance(IV_SIZE)
    val aes = AESEncryptionScheme.getInstance(AES_KEY_LENGTH, AES_MODE, iv)
    val encryptedMessage = aes.encrypt(key, paddedMessage)

    val bytes = encryptedMessage.convertToByteArray.getBytes
    val encrypted = Base64.getEncoder().encodeToString(bytes)
    val ivString =  Base64.getEncoder().encodeToString(iv.getBytes)
    (encrypted, ivString)
  }

  /** Returns the AES decryption of the given base64 encoded String as a String */
  def decryptAES(content: String, key: FiniteByteArrayElement, iv: String): String = {
    val byteSpace = ByteArrayMonoid.getInstance()
    val bytes = Base64.getDecoder().decode(content)
    val toDecrypt = byteSpace.getElement(bytes)
    val ivBytes = ByteArray.getInstance(Base64.getDecoder().decode(iv) :_*)
    val aes = AESEncryptionScheme.getInstance(AES_KEY_LENGTH, AES_MODE, ivBytes)
    val decryptedMessage = aes.decrypt(key, toDecrypt)
    val pkcs = PKCSPaddingScheme.getInstance(PADDING_SIZE)
    val unpaddedMessage = pkcs.unpad(decryptedMessage)

    new String(unpaddedMessage.convertToByteArray.getBytes, StandardCharsets.UTF_8)
  }

  /** Return the AES key in the given file string as a unicrypt object */
  def readAESKey(path: Path): FiniteByteArrayElement = {
    val keyString = IO.asString(path)
    val aes = AESEncryptionScheme.getInstance()
    aes.getEncryptionKeySpace.getElementFrom(keyString)
  }

  /** Return the AES key in the given file bytes as a unicrypt object */
  def readAESKeyBytes(path: Path): FiniteByteArrayElement = {
    val keyBytes = IO.asBytes(path)
    val bytes = ByteArray.getInstance(keyBytes :_*)
    val aes = AESEncryptionScheme.getInstance()
    aes.getEncryptionKeySpace.getElementFrom(bytes)
  }

  /** Return a random AES key as a byte array */
  def randomAESKey: Array[Byte] = {
    val aes = AESEncryptionScheme.getInstance()
    aes.generateSecretKey().convertToByteArray.getBytes
  }

  /** Return a random AES key as a unicrypt converted String */
  def randomAESKeyString: String = {
    val aes = AESEncryptionScheme.getInstance()
    aes.generateSecretKey().convertToString
  }

  /** Return a random AES key as a unicrypt object */
  def randomAESKeyElement: FiniteByteArrayElement = {
    val aes = AESEncryptionScheme.getInstance()
    aes.generateSecretKey()
  }

  /** Reads a private RSA key from the given file
   *
   *  The file must be in pkcs8 PEM format. Example generating and
   *  converting commands (the second produces the right file)
   *
   *  ssh-keygen -t rsa -b 4096 -f keys/id_rsa -q -N ""
   *  openssl pkcs8 -topk8 -inform PEM -outform PEM -in keys/id_rsa -out keys/id_rsa.pem -nocrypt
   *
   */
  def readPrivateRsa(path: Path): RSAPrivateKey = {
    var pkpem = IO.asString(path)
    readPrivateRsa(pkpem)
  }

  /** Reads a public RSA key from the given file
   *
   *  The file must be in PEM format. Example generating and
   *  converting commands (the second produces the right file)
   *
   *  ssh-keygen -t rsa -b 4096 -f keys/id_rsa -q -N ""
   *  openssl rsa -in keys/id_rsa -pubout > keys/id_rsa.pub.pem
   *
   */
  def readPublicRsa(path: Path): RSAPublicKey = {
    val pkpem = IO.asString(path)
    readPublicRsa(pkpem)
  }

  /** Reads a private RSA key from the given String
   *
   *  The file must be in pkcs8 PEM format. Example generating and
   *  converting commands (the second produces the right file)
   *
   *  ssh-keygen -t rsa -b 4096 -f keys/id_rsa -q -N ""
   *  openssl pkcs8 -topk8 -inform PEM -outform PEM -in keys/id_rsa -out keys/id_rsa.pem -nocrypt
   *
   */
  def readPrivateRsa(str: String): RSAPrivateKey = {
    var pkpem = str
    pkpem = pkpem.replace("-----BEGIN PRIVATE KEY-----\n", "")
    pkpem = pkpem.replace("-----END PRIVATE KEY-----", "")
    val decoded = Base64.getMimeDecoder().decode(pkpem)
    val spec = new PKCS8EncodedKeySpec(decoded)
    val kf = KeyFactory.getInstance("RSA")

    kf.generatePrivate(spec).asInstanceOf[RSAPrivateKey]
  }

  /** Reads a public RSA key from the given String
   *
   *  The file must be in PEM format. Example generating and
   *  converting commands (the second produces the right file)
   *
   *  ssh-keygen -t rsa -b 4096 -f keys/id_rsa -q -N ""
   *  openssl rsa -in keys/id_rsa -pubout > keys/id_rsa.pub.pem
   *
   */
  def readPublicRsa(str: String): RSAPublicKey = {
    var pkpem = str
    pkpem = pkpem.replace("-----BEGIN PUBLIC KEY-----\n", "")
    pkpem = pkpem.replace("-----END PUBLIC KEY-----", "")
    val decoded = Base64.getMimeDecoder().decode(pkpem)
    val spec: X509EncodedKeySpec = new X509EncodedKeySpec(decoded)
    val kf = KeyFactory.getInstance("RSA")

    kf.generatePublic(spec).asInstanceOf[RSAPublicKey]
  }
}

/** Represents a key maker trustee
 *
 *  Methods to create shares and partially decrypt votes.
 *  Mixes in the libmix KeyMaker trait.
 */
object KeyMakerTrustee extends KeyMaker {

  override val logger = LoggerFactory.getLogger(KeyMakerTrustee.getClass)

  /** Creates a key share
   *
   *  Returns the key share and proof of knowledge as an libmix EncryptionKeyShareDTO.
   *  Returns the private key part of the share as a unicrypt converted String
   */
  def createKeyShare(id: String, cSettings: CryptoSettings): (EncryptionKeyShareDTO, String) = {

    val (encryptionKeyShareDTO, privateKey) = createShare(id, cSettings)

    (encryptionKeyShareDTO, privateKey.convertToString)
  }

  /** Partially decrypt a ciphertext with the private part of a share
   *
   *  Returns the partial decryption and proof of knowledge as an nMix EncryptionKeyShareDTO.
   */
  def partialDecryption(id: String, votes: Seq[String],
    privateShare: String, cSettings: CryptoSettings): PartialDecryptionDTO = {

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val v = votes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v).asInstanceOf[Pair]).seq
    val secretKey = cSettings.group.getZModOrder().getElementFrom(privateShare)

    partialDecrypt(v, secretKey, id, cSettings)
  }
}

/** Represents a shuffling trustee
 *
 *  Methods to mix votes.
 *  Mixes in the libmix Mixer trait.
 */
object MixerTrustee extends Mixer {

  override val logger = LoggerFactory.getLogger(MixerTrustee.getClass)

  /** Shuffle the provided votes
   *
   *  Returns the shuffle and proof of knowledgeas an libmix ShuffleResultDTO
   */
  def shuffleVotes(votes: Seq[String], publicKey: String, id: String, cSettings: CryptoSettings): ShuffleResultDTO = {
    logger.debug("Mixer shuffle..")

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val pk = keyPairGen.getPublicKeySpace().getElementFrom(publicKey)

    logger.trace("Convert votes..")

    val vs = votes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq

    logger.trace("Mixer creating shuffle..")

    shuffle(Util.tupleFromSeq(vs), pk, cSettings, id)
  }

  /** Performs the offline phase of the shuffle
   *
   *  Returns the permutation data and the permutation proof
   */
  def preShuffleVotes(voteCount: Int, publicKey: String, id: String,
    cSettings: CryptoSettings): (PermutationProofDTO, PermutationData) = {

    logger.debug("Mixer offline phase..")

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val pk = keyPairGen.getPublicKeySpace().getElementFrom(publicKey)

    preShuffle(voteCount, pk, cSettings, id)
  }

  /** Performs the online phase of the shuffle
   *
   *  Requires data from the online phase
   *  Returns the shuffle and proof of knowledgeas an libmix ShuffleResultDTO
   */
  def shuffleVotes(votesString: Seq[String], preData: PreShuffleData,
    publicKey: String, id: String, cSettings: CryptoSettings): ShuffleResultDTO = {

    logger.debug("Mixer online phase..")
    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val pk = keyPairGen.getPublicKeySpace().getElementFrom(publicKey)
    logger.trace("Convert votes..")

    val votes = votesString.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq

    logger.trace("Mixer creating shuffle..")

    shuffle(Util.tupleFromSeq(votes), preData.pData, preData.proof, pk, cSettings, id)
  }
}
