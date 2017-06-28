package org.nvotes.mix

import java.nio.file.Paths
import java.nio.charset.StandardCharsets
import java.util.UUID

import org.scalatest.FlatSpec

import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModElement
import org.nvotes.libmix._

/** Tests serialization of artifacts
 *
 */
class SerializationSpec extends FlatSpec {

  /* "config" should "serialize/deserialze ok" in {

    assert(true)
  }

  "shares" should "serialize/deserialze ok" in {

    assert(true)
  }

  "publickey" should "serialize/deserialze ok" in {

    assert(true)
  }

  "ballots" should "serialize/deserialze ok" in {

    assert(true)
  }

  "shuffles" should "serialize/deserialze ok" in {

    assert(true)
  }

  "decryptions" should "serialize/deserialze ok" in {

    assert(true)
  }

  "plaintexts" should "serialize/deserialze ok" in {

    assert(true)
  }*/


  def randomConfig: Config = ???
  def randomShare: Share = ???
  def randomPublicKey: GStarModElement = ???
  def randomBallots: Ballots = ???
  def randomShuffleResult: ShuffleResultDTO = ???
  def randomDecryption: PartialDecryptionDTO = ???
  def randomPlaintext: Plaintexts = ???

}