package org.nvotes.mix

import java.nio.file.Paths
import java.nio.file.Files
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.nio.charset.StandardCharsets._
import scala.util.Random

import org.scalatest.FlatSpec

import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

import org.nvotes.libmix._


/** Tests serialization of artifacts
 *
 */
class SerializationSpec extends FlatSpec {

  "config" should "serialize/deserialize ok" in {
    val config = randomConfig
    val path = IO.writeTemp(config.asJson.noSpaces)
    val read = IO.asString(path)
    val config_ = decode[Config](read).right.get

    assert(config == config_)
  }

  "share" should "serialize/deserialize ok" in {
    val share = randomShare
    val path = IO.writeTemp(share.asJson.noSpaces)
    val read = IO.asString(path)
    val share_ = decode[Share](read).right.get

    assert(share == share_)
  }

  "publickey" should "serialize/deserialize ok" in {
    val (pk,scheme) = randomPublicKey
    val path = IO.writeTemp(pk.convertToString)
    val read = IO.asString(path)
    val pk_ = scheme.getKeyPairGenerator().getPublicKeySpace().getElementFrom(read)
    assert(pk == pk_)
  }

  "ballots" should "serialize/deserialize ok" in {
    val ballots = randomBallots
    val (path, _) = IO.writeBallotsTemp(ballots)
    val read = Files.newInputStream(path)
    val (ballots_, _) = IO.readBallots(read)

    assert(ballots == ballots_)
  }

  "shuffle" should "serialize/deserialize ok" in {
    val shuffle = randomShuffleResult
    val (path, _) = IO.writeShuffleResultTemp(shuffle)
    val read = Files.newInputStream(path)
    val (shuffle_, _) = IO.readShuffleResult(read)
    read.close()

    assert(shuffle == shuffle_)
  }

  "decryption" should "serialize/deserialize ok" in {
    val decryption = randomDecryption
    val (path, _) = IO.writeDecryptionTemp(decryption)
    val read = Files.newInputStream(path)
    val (decryption_, _) = IO.readDecryption(read)
    read.close()

    assert(decryption == decryption_)
  }

  "plaintexts" should "serialize/deserialize ok" in {
    val plaintexts = randomPlaintexts
    val (path, _) = IO.writePlaintextsTemp(plaintexts)
    val read = Files.newInputStream(path)
    val (plaintexts_, _) = IO.readPlaintexts(read)
    read.close()

    assert(plaintexts == plaintexts_)
  }

  "config statement" should "serialize/deserialize ok" in {
    val configS = randomConfigS
    val path = IO.writeTemp(configS.asJson.noSpaces)
    val read = IO.asString(path)
    val configS_ = decode[ConfigStatement](read).right.get

    assert(configS == configS_)
  }

  "share statement" should "serialize/deserialize ok" in {
    val data = randomShareS
    val path = IO.writeTemp(data.asJson.noSpaces)
    val read = IO.asString(path)
    val data_ = decode[ShareStatement](read).right.get

    assert(data == data_)
  }

  "public key statement" should "serialize/deserialize ok" in {
    val data = randomPublicKeyS
    val path = IO.writeTemp(data.asJson.noSpaces)
    val read = IO.asString(path)
    val data_ = decode[PublicKeyStatement](read).right.get

    assert(data == data_)
  }

  "ballots statement" should "serialize/deserialize ok" in {
    val data = randomBallotsS
    val path = IO.writeTemp(data.asJson.noSpaces)
    val read = IO.asString(path)
    val data_ = decode[BallotsStatement](read).right.get

    assert(data == data_)
  }

  "mix statement" should "serialize/deserialize ok" in {
    val data = randomMixS
    val path = IO.writeTemp(data.asJson.noSpaces)
    val read = IO.asString(path)
    val data_ = decode[MixStatement](read).right.get

    assert(data == data_)
  }

  "decryption statement" should "serialize/deserialize ok" in {
    val data = randomDecryptionS
    val path = IO.writeTemp(data.asJson.noSpaces)
    val read = IO.asString(path)
    val data_ = decode[DecryptionStatement](read).right.get

    assert(data == data_)
  }

  "plaintexts statement" should "serialize/deserialize ok" in {
    val data = randomPlaintextsS
    val path = IO.writeTemp(data.asJson.noSpaces)
    val read = IO.asString(path)
    val data_ = decode[PlaintextsStatement](read).right.get

    assert(data == data_)
  }

  /** Helper functions to generate random test data
   *
   */

  def randomConfig: Config = {
    Config(str, str, str, str, int_, str, strs)
  }

  def randomShare: Share = {
    val proof = SigmaProofDTO(str, str, str)
    val share = EncryptionKeyShareDTO(proof, str)
    Share(share, str, str)
  }

  def randomPublicKey: (GStarModElement, ElGamalEncryptionScheme) = {
    val grp = GStarModSafePrime.getFirstInstance(2048)
    val gen = grp.getDefaultGenerator()
    val elGamal = ElGamalEncryptionScheme.getInstance(gen)
    val keyPair = elGamal.getKeyPairGenerator().generateKeyPair()
    val privateKey = keyPair.getFirst()
    val publicKey = keyPair.getSecond().asInstanceOf[GStarModElement]
    (publicKey, elGamal)
  }

  def randomBallots: Ballots = Ballots(strs)

  def randomShuffleResult: ShuffleResultDTO = {
    val mixproof = MixProofDTO(str, str, str, strs)
    val permproof = PermutationProofDTO(str, str, str, strs, strs)
    val proof = ShuffleProofDTO(mixproof, permproof, str)
    ShuffleResultDTO(proof, strs)
  }

  def randomDecryption: PartialDecryptionDTO = {
    val proof = SigmaProofDTO(str, str, str)
    PartialDecryptionDTO(strs, proof)
  }

  def randomPlaintexts: Plaintexts = Plaintexts(strs)

  def randomConfigS: ConfigStatement = {
    ConfigStatement(str)
  }

  def randomShareS: ShareStatement = {
    ShareStatement(str, str, int_)
  }

  def randomPublicKeyS: PublicKeyStatement = {
    PublicKeyStatement(str, str, str, int_)
  }

  def randomBallotsS: BallotsStatement = {
    BallotsStatement(str, str, int_)
  }

  def randomMixS: MixStatement = {
    MixStatement(str, str, str, int_, int_)
  }

  def randomDecryptionS: DecryptionStatement = {
    DecryptionStatement(str, str, str, int_)
  }

  def randomPlaintextsS: PlaintextsStatement = {
    PlaintextsStatement(str, str, str, int_)
  }

  def str: String = {
    val length = 20 + Random.nextInt(200)
    val bytes = new Array[Byte](length)
    Random.nextBytes(bytes)

    new String(bytes, StandardCharsets.UTF_8).replace("\n", "").replace("\r", "")
    // UUID.randomUUID().toString
  }

  def strs: Array[String] = {
    Array.fill(Random.nextInt(20))(str)
  }

  def int_ = Random.nextInt
}