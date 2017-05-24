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

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._, io.circe.generic.JsonCodec
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import org.nvotes.libmix._

/** A Statement represents some assertion an authority makes when signing
 *  the Statement's data.
 *
 *  Signatures corresponding to statements allow verifying the correct
 *  execution of the protocol. These checks must be carried out by the
 *  protocol's Actions.
 *
 *  Statements are serialized as json Strings before being signed.
 *
 */
sealed trait Statement {
  /** Returns the RSA signature of this statement */
  def sign(privateKey: RSAPrivateKey): Array[Byte] = {
    Crypto.sign(this.asJson.noSpaces, privateKey)
  }

  /** Returns true if the the RSA signature of this statement is correct */
  def verify(signature: Array[Byte], publicKey: RSAPublicKey): Boolean = {
    Crypto.verify(this.asJson.noSpaces, signature, publicKey)
  }
}

/** Produced by bootstrap. Each authority signs the configuration. Cardinality = (1, n)
 *
 */
case class ConfigStatement(configHash: String) extends Statement

/** Produce by each authority. Each authority signs their share. Cardinality = (n, 1)
 *
 *  The share S belongs to configuration C and item I
 */
case class ShareStatement(shareHash: String, configHash: String, item: Int) extends Statement


/** Produced by authority 1. Each authority signs the public key. Cardinality = (1, n)
 *
 *  The public Key P belongs to configuration C and item I
 *  The shares S belong to configuration C
 *  The shares S yield the public key P
 *  The shares S each produced by the right authority
 *  The shares S each had a valid POK
 *
 */
case class PublicKeyStatement(publicKeyHash: String, sharesHash: String, configHash: String, item: Int) extends Statement

/** Produced by ballot box. The ballot box signs the ballots. Cardinality = (1, 1)
 *
 *  The ballots B belong to configuration C
 *
 */
 case class BallotsStatement(ballotsHash: String, configHash: String, item: Int) extends Statement

 /** Produced by each authority. Each authority signs their mix, as well as other mixes. Cardinality = (n, n)
 *
 *  The mix M belongs to configuration C and item I
 *  The mix/ballot P belongs to configuration C
 *  Mixing P yields mix M
 */
 case class MixStatement(mixHash: String, parentHash: String, configHash: String, item: Int, auth: Int) extends Statement


/** Produced by each authority. Each authority signs their decryption. Cardinality = (n, 1)
 *
 *  The decryption D belongs to configuration C
 *  The mix M decrypts to D
 *  The mix M is the nth mix starting from the ballots, where n is the number of authorities
 */
case class DecryptionStatement(decryptionHash: String, mixHash: String, configHash: String, item: Int) extends Statement


/** Produced by auth 1. Each authority signs the decryption. Cardinality = (1, n)
 *
 *  The shares D belong to configuration C
 *  The shares D yield the plaintext P
 *  The shares D each produced by the right authority
 *  The shares D each had a valid POK
 */
case class PlaintextsStatement(plaintextsHash: String, decryptionsHash: String, configHash: String, item: Int) extends Statement


/** Entry point for constructing Statments. */
object Statement {

  /** Returns the config statement for the given Config object */
  def getConfigStatement(config: Config) = {
    val hash = Crypto.sha512(config.asJson.noSpaces)
    ConfigStatement(hash)
  }

  /** Returns the share statement for the given Share object, config hash and item */
  def getShareStatement(share: Share, configHash: String, item: Int) = {
    val shareHash = Crypto.sha512(share.asJson.noSpaces)
    ShareStatement(shareHash, configHash, item)
  }

  /** Returns the share statement for the given share shash, config hash and item */
  def getShareStatement(shareHash: String, configHash: String, item: Int) = {
    ShareStatement(shareHash, configHash, item)
  }

  /** Returns the public key statement for the given public key String,
    sequence of share Strings, config hash and item */
  def getPublicKeyStatement(publicKey: String, shares: Seq[String], configHash: String, item: Int) = {
    val publicKeyHash = Crypto.sha512(publicKey.asJson.noSpaces)
    val sharesHash = Crypto.sha512(shares.asJson.noSpaces)

    PublicKeyStatement(publicKeyHash, sharesHash, configHash, item)
  }

  /** Returns the ballots statement for the ballot hash, config hash and item */
  def getBallotsStatement(ballotHash: String, configHash: String, item: Int) = {
    BallotsStatement(ballotHash, configHash, item)
  }

  /** Returns the mix statement for the mix hash, parent mix hash,
    config hash, item and authority */
  def getMixStatement(mixHash: String, parentHash: String, configHash: String, item: Int, auth: Int) = {
    MixStatement(mixHash, parentHash, configHash, item, auth)
  }

  /** Returns the decryption statement for the decryption hash, mix hash,
    config hash, and item */
  def getDecryptionStatement(decryptionHash: String, mixHash: String, configHash: String, item: Int) = {
    DecryptionStatement(decryptionHash, mixHash, configHash, item)
  }

  /** Returns the plaintexts statement for the plaintexts hash,
    decryptions hash, config hash and item */
  def getPlaintextsStatement(plaintextsHash: String, decryptionsHash: String, configHash: String, item: Int) = {

    PlaintextsStatement(plaintextsHash, decryptionsHash, configHash, item)
  }
}