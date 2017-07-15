package org.nvotes.mix

import java.nio.file.Paths
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

  "config" should "serialize/deserialze ok" in {
    val config = randomConfig
    val path = IO.writeTemp(config.asJson.noSpaces)
    val read = IO.asString(path)
    val config_ = decode[Config](read).right.get

    assert(config == config_)
  }

  "share" should "serialize/deserialze ok" in {
    val share = randomShare
    val path = IO.writeTemp(share.asJson.noSpaces)
    val read = IO.asString(path)
    val share_ = decode[Share](read).right.get

    assert(share == share_)
  }

  "publickey" should "serialize/deserialze ok" in {
    val (pk,scheme) = randomPublicKey
    val path = IO.writeTemp(pk.convertToString)
    val read = IO.asString(path)
    val pk_ = scheme.getKeyPairGenerator().getPublicKeySpace().getElementFrom(read)
    assert(pk == pk_)
  }

  "ballots" should "serialize/deserialze ok" in {
    val ballots = randomBallots
    val path = IO.writeTemp(ballots.asJson.noSpaces)
    val read = IO.asString(path)
    val ballots_ = decode[Ballots](read).right.get

    assert(ballots == ballots_)
  }

  "shuffle" should "serialize/deserialze ok" in {
    val shuffle = randomShuffleResult
    val path = IO.writeTemp(shuffle.asJson.noSpaces)
    val read = IO.asString(path)
    val shuffle_ = decode[ShuffleResultDTO](read).right.get

    assert(shuffle == shuffle_)
  }

  "decryption" should "serialize/deserialze ok" in {
    val decryption = randomDecryption
    val path = IO.writeTemp(decryption.asJson.noSpaces)
    val read = IO.asString(path)
    val decryption_ = decode[PartialDecryptionDTO](read).right.get

    assert(decryption == decryption_)
  }

  "plaintexts" should "serialize/deserialze ok" in {
    val plaintexts = randomPlaintexts
    val path = IO.writeTemp(plaintexts.asJson.noSpaces)
    val read = IO.asString(path)
    val plaintexts_ = decode[Plaintexts](read).right.get

    assert(plaintexts == plaintexts_)
  }


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

  def str: String = {
    val length = 20 + Random.nextInt(200)
    val bytes = new Array[Byte](length)
    Random.nextBytes(bytes)

    new String(bytes, StandardCharsets.UTF_8)
  }

  def strs: Array[String] = {
    Array.fill(Random.nextInt(20))(str)
  }

  def int_ = Random.nextInt
}