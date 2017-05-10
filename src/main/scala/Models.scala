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

package org.nvotes.trustee

import org.nvotes.libmix._

/** The configuration for a protocol run, typically for an election
 *
 *  Some of these are parameterized by authority and item, needing
 *  methods.
 *
 *  The trustees and ballotbox field are public keys. They must be formatted without
 *  spaces, using \n as markers for newlines. Read by Crypto.ReadPublicRSA
 *
 *  Generate files with this format with the GenConfig Command
 */
case class Config(id: String, name: String, modulus: String, generator: String,
	items: Int, ballotbox: String, trustees: Array[String]) {
  override def toString() = s"Config($id $name $items)"
}

/** A share of the distributed key.
 *
 *  The public part is stored as an nMix EncryptionKeyShareDTO , which
 *  contains the share and the proof of knowledge.
 *
 *  The private part is aes encrypted by the authority.
 *
 */
case class Share(share: EncryptionKeyShareDTO, encryptedPrivateKey: String, aesIV: String)

/** Permutation data resulting from offline phase of mixing
 *
 *  In the current implementation this data is only stored locally
 *  in memory. For this reason
 *
 *  1. The data does not need to be encrypted.
 *  2. The data does not need to be serialized.
 *
 *  Changing the implementation to store this remotely _must_
 *  include encryption of permutation data.
 */
case class PreShuffleData(proof: PermutationProofDTO, pData: PermutationData)

/** Ballots provided by the ballotbox in unicrypt format. Encrypted */
case class Ballots(ballots: Seq[String])

/** Plaintexts jointly encrypted by authorities after mixing, in unicrypt format */
case class Plaintexts(plaintexts: Seq[String])

/** Convenience class to pass around relevant data  */
case class Context(config: Config, section: BoardSectionInterface, trusteeCfg: TrusteeConfig,
  position: Int, cSettings: CryptoSettings)