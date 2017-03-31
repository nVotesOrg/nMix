package org.nvotes.trustee

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.crypto.encoder.classes.ZModPrimeToGStarModSafePrime
import ch.bfh.unicrypt.math.algebra.general.classes.Pair
import org.nvotes.libmix._

import java.nio.charset.StandardCharsets
import scala.collection.mutable.ListBuffer

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/** Actions are operations that advance the protocol.
 *
 *  Actions are called as a result of matching conditions.
 */
sealed trait Action extends Ordered[Action] {

  val logger = LoggerFactory.getLogger(getClass)

  /** Returs the config hash after checking that it has been self-signed correctly
   *
   *  If any of the checks fail, returns the empty string "".
   *
   *  All Actions must check that they are being executed in the context
   *  of a configuration that has been previously approved. Actions should
   *  therefore call this method first.
   */
  def getValidConfigHash(ctx: Context): String = {

    logger.info("verifying config statement and signature")

    val expected = Statement.getConfigStatement(ctx.config)
    val expectedString = expected.asJson.noSpaces

    val ok = ctx.section.getConfigStatement.map(expectedString == _).getOrElse(false)
    if(!ok) {
      logger.error("statement mismatch")
      return ""
    }

    ctx.section.getConfigSignature(ctx.position).map{ sig =>
      val ok = expected.verify(sig, ctx.trusteeCfg.publicKey)
      if(ok) {
        expected.configHash
      }
      else {
        logger.error("config signature error")
        ""
      }
    }.getOrElse("")
  }

  /** Action operations go here */
  def execute(): Result

  /** The priority of this Action
   *
   *  Actions at the beginning of the protocol should be
   *  prioritized to enhance parallelism
   *
   *  Lower values have higher priority
   */
  val priority: Int

  def compare (that: Action) = {
    priority.compare(that.priority)
  }
}

/** Used to stop the protocol.
 *
 *  Examples are pause and error condition rules.
 */
case class StopAction(message: String) extends Action {
  /** This value does not matter as StopAction is
    only issued at the global level */
  val priority = 1
  def execute(): Result = Stop(message)
}

/** Validates and signs the config if accepted by this authority.
 *
 *  The config will not be accepted if
 *  - any of the trustees is not trusted by this authority
 *  - the number of trustees is smaller than 2
 *  - the statement does not match the config
 *
 *  Other checks may be added (eg depending on list of accepted elections)
 */
case class ValidateConfig(ctx: Context) extends Action {
  /** This value does not matter as ValidateConfig is
    only issued at the global level */
  val priority = 1

  def execute(): Result = {

    val config = ctx.config

    val expected = Statement.getConfigStatement(config)
    val expectedString = expected.asJson.noSpaces
    val result = ctx.section.getConfigStatement.map(expectedString == _).getOrElse(false)

    if(result) {

      if(!ctx.trusteeCfg.peers.contains(Crypto.readPublicRsa(config.ballotbox))) {
        logger.error(s"ballotbox is not in peers ${config.ballotbox}")
        return Error(s"ballotbox is not in peers ${config.ballotbox}")
      }

      if(config.trustees.size < 2) {
        logger.error(s"Insufficient trustees: ${config.trustees.size}")
        return Error(s"Insufficient trustees: ${config.trustees.size}")
      }

      config.trustees.map(Crypto.readPublicRsa(_)).foreach { t =>
        if(!ctx.trusteeCfg.peers.contains(t)) {
          logger.error(s"trustee not in peers $t")
          return Error(s"trustee not in peers $t")
        }
      }

      val signature = expected.sign(ctx.trusteeCfg.privateKey)
      val file = IO.writeTemp(signature)
      ctx.section.addConfigSig(file, ctx.position)

      Ok
    }
    else {
      // FIXME LOG
      println(s"statements do not match, $expected")
      return Error(s"statements do not match, $expected")
    }
  }

  override def toString = s"ValidateConfig"
}

/** Adds this authority's share.
 *
 *  The authority creates the share, creates the statement, and signs it.
 *  The private share is encrypted with aes, and included in the share.
 */
case class AddShare(ctx: Context, item: Int) extends Action {
  val priority = 1

  def execute(): Result = {

    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"AddShare: invalid config")
    }

    // the modulus of public keys is unique, can use it as proverId
    // http://crypto.stackexchange.com/questions/8857/uniqueness-of-the-rsa-public-modulus
    val modulusStr = ctx.trusteeCfg.publicKey.getModulus.toString
    val (share, privateKey) = KeyMakerTrustee.createKeyShare(modulusStr, ctx.cSettings)

    // encrypt the share private key
    val encrypted = Crypto.encryptAES(privateKey, ctx.trusteeCfg.aesKey)

    val fullShare = Share(share, encrypted)
    val statement = Statement.getShareStatement(fullShare, configHash, item)
    val signature = statement.sign(ctx.trusteeCfg.privateKey)

    val file1 = IO.writeTemp(fullShare.asJson.noSpaces)
    val file2 = IO.writeTemp(statement.asJson.noSpaces)
    val file3 = IO.writeTemp(signature)

    ctx.section.addShare(file1, file2, file3, item, ctx.position)

    Ok
  }

  override def toString = s"AddShare($item)"
}

/** Add the public key, or signs it if we are not #1 authority.
 *
 *  This Action should be implemented carefully as privacy properties
 *  depend on the public key being generated jointly by all the authorities.
 *
 *  Authority #1 is responsible for creating the public
 *  key from the shares of all the authorities. Once this has occured,
 *  the rest of authorities validate it by recreating it themselves.
 *
 *  The public key is created and signed if
 *
 *  - the configuration is accepted
 *  - the shares have correct statements, signatures and pok
 *  - the number of shares is equal to number of authorities
 *
 *  Authorities other than #1 reuse the statement created by #1
 *  and sign it if everything is correct and the public key is
 *  identical to their locally created one.
 */
case class AddOrSignPublicKey(ctx: Context, item: Int) extends Action {
  val priority = 2

  def execute(): Result = {
    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"AddShare: invalid config")
    }

    val collectedShares = new ListBuffer[Share]()

    // verify all shares
    (1 to ctx.config.trustees.size).map { auth =>

      logger.info(s"item $item processing share $auth..")
      val share = ctx.section.getShare(item, auth).map(decode[Share](_).right.get).get
      val shareStmt = ctx.section.getShareStatement(item, auth).get
      val shareSig = ctx.section.getShareSignature(item, auth).get

      val expected = Statement.getShareStatement(share, configHash, item)
      val expectedString = expected.asJson.noSpaces

      if(expectedString == shareStmt) {
        logger.info(s"item $item processing share $auth, statement OK")
        val authPk = Crypto.readPublicRsa(ctx.config.trustees(auth - 1))

        val ok = expected.verify(shareSig, authPk)
        if(ok) {
          logger.info(s"item $item processing share $auth, signature OK")
          val pokOk = Verifier.verifyKeyShare(share.share, ctx.cSettings, authPk.getModulus.toString)
          logger.info(s"item $item processing share $auth, pok $pokOk")
          if(pokOk) {
            collectedShares += share
          }
          else {
            // the error will be caused below
            logger.warn(s"item $item processing share $auth, pok NOT ok")
          }
        }
        else {
          // the error will be caused below
          logger.warn(s"item $item processing share $auth, signature NOT ok")
        }
      } else {
        // the error will be caused below
        logger.warn(s"item $item processing share $auth, statement NOT ok")
      }
    }

    if(collectedShares.length == ctx.config.trustees.size) {
      val shares = collectedShares.map { share =>
        Util.getPublicKeyFromString(share.share.keyShare, ctx.cSettings.generator)
      }
      val sharesStr = collectedShares.map(_.share.keyShare)
      // the public key is the multiplcation of each share (or the addition of each exponent)
      val publicKey = shares.reduce( (a,b) => a.apply(b) ).convertToString

      if(ctx.position == 1) {
        //  send and sign public key
        val statement = Statement.getPublicKeyStatement(publicKey, sharesStr, configHash, item)
        val signature = statement.sign(ctx.trusteeCfg.privateKey)

        val file1 = IO.writeTemp(publicKey)
        val file2 = IO.writeTemp(statement.asJson.noSpaces)
        val file3 = IO.writeTemp(signature)

        ctx.section.addPublicKey(file1, file2, file3, item, ctx.position)
      }
      else {
        // sign public key if statements match
        val publicKey = ctx.section.getPublicKey(item).getOrElse("")
        val expected = Statement.getPublicKeyStatement(publicKey, sharesStr, configHash, item)
        val expectedString = expected.asJson.noSpaces
        val ok = ctx.section.getPublicKeyStatement(item).map(expectedString == _).getOrElse(false)

        if(ok) {
          logger.info(s"item $item public key statement OK")
          val sig = expected.sign(ctx.trusteeCfg.privateKey)
          val file1 = IO.writeTemp(sig)

          ctx.section.addPublicKeySignature(file1, item, ctx.position)
        }
        else {
          logger.error(s"public key statement mismatch")
          return Error(s"public key statement mismatch")
        }
      }
    }
    else {
      logger.error(s"not enough shares collected ${collectedShares.length}")
      return Error(s"not enough shares collected ${collectedShares.length}")
    }

    Ok
  }

  override def toString = s"AddOrSignPublicKey($item)"
}

/** Adds this authority's preshuffle data
 *
 *  To calculate permutation only the number of votes cast
 *  is required, so these actions can occur in parallel
 *  as soon as the ballots have been posted.
 *
 *  In the current implementation, this data is stored in
 *  memory at the board, so we do not need to encrypt
 *  the permutation data. If sending to the repository
 *  it _must_ be encrypted.
 */
case class AddPreShuffleData(ctx: Context, item: Int) extends Action {
  val priority = 3

  def execute(): Result = {
    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"AddPreShuffleData: invalid config")
    }
    logger.info("starting..")

    val ballots = decode[Ballots](ctx.section.getBallots(item).get).right.get
    val publicKey = ctx.section.getPublicKey(item).get
    val modulusStr = ctx.trusteeCfg.publicKey.getModulus.toString

    val (proof, data) = MixerTrustee.preShuffleVotes(ballots.ballots.length, publicKey, modulusStr, ctx.cSettings)

    ctx.section.addPreShuffleDataLocal(PreShuffleData(proof, data), item, ctx.position)

    Ok
  }

  override def toString = s"AddPreShuffleData($item)"
}


/** Adds this authority's mix
 *
 *  If this authority is #1, it will mix the votes provided by the
 *  ballot box. Otherwise it will mix the votes resulting from
 *  mix n - 1, where n is this authority's position.
 *
 *  The authority will add the mix, statement and signature for
 *  this mix.
 */
case class AddMix(ctx: Context, item: Int) extends Action {
  val priority = 3
  val myMixPosition = Protocol.getMixPosition(ctx.position, item, ctx.config.trustees.size)

  def execute(): Result = {
    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"AddMix: invalid config")
    }

    val previousMixAuth = Protocol.getMixPositionInverse(myMixPosition - 1, item, ctx.config.trustees.size)
    val (previousBallots, previousStr) = if(myMixPosition == 1) {
      val ballots = ctx.section.getBallots(item).get
      val bs = decode[Ballots](ballots).right.get
      (bs.ballots, ballots)
    }
    else {
      val mix = ctx.section.getMix(item, previousMixAuth).get
      val m = decode[ShuffleResultDTO](mix).right.get
      (m.votes, mix)
    }

    val publicKey = ctx.section.getPublicKey(item).get
    val modulusStr = ctx.trusteeCfg.publicKey.getModulus.toString

    val preShuffleData = ctx.section.getPreShuffleDataLocal(item, ctx.position).get

    // val newMix = MixerTrustee.shuffleVotes(previousBallots, publicKey, modulusStr, ctx.cSettings)
    logger.info("performing online phase with pre-shuffle data")
    val newMix = MixerTrustee.shuffleVotes(previousBallots, preShuffleData, publicKey, modulusStr, ctx.cSettings)
    val mixHash = Crypto.sha512(newMix.asJson.noSpaces)
    val parentHash = Crypto.sha512(previousStr)

    val statement = Statement.getMixStatement(mixHash, parentHash, configHash, item, ctx.position)
    val signature = statement.sign(ctx.trusteeCfg.privateKey)

    val file1 = IO.writeTemp(newMix.asJson.noSpaces)
    val file2 = IO.writeTemp(statement.asJson.noSpaces)
    val file3 = IO.writeTemp(signature)

    ctx.section.addMix(file1, file2, file3, item, ctx.position)

    Ok
  }

  override def toString = s"AddMix($item, $myMixPosition)"
}

/** Verify another authority's mix
 *
 *  The protocol requires all mixes to be verified by all authorities.
 *  This Action performs verification of a mix at n by an authorty != n.
 *
 *  Verification checks the statement, the signature and the proof of shuffle.
 *  Verifying the proof of shuffle requires the pre and post votes. If
 *  this is mix #1, the pre votes should be those provided by the ballot box.
 *  Otherwise they should be the output of the previous mix.
 */
case class VerifyMix(ctx: Context, item: Int, auth: Int) extends Action {
  val priority = 4

  def execute(): Result = {
    logger.info(s"item $item, target auth $auth")

    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"VerifyMix: invalid config")
    }

    val mix = ctx.section.getMix(item, auth).map(decode[ShuffleResultDTO](_).right.get).get
    val mixStmt = ctx.section.getMixStatement(item, auth).get
    val mixSig = ctx.section.getMixSignature(item, auth, auth).get

    val mixPosition = Protocol.getMixPosition(auth, item, ctx.config.trustees.size)
    val previousMixAuth = Protocol.getMixPositionInverse(mixPosition - 1, item, ctx.config.trustees.size)
    val (parentBallots, parentStr) = if(mixPosition == 1) {
      val ballots = ctx.section.getBallots(item).get
      val bs = decode[Ballots](ballots).right.get
      (bs.ballots, ballots)
    }
    else {
      val mix = ctx.section.getMix(item, previousMixAuth).get
      val m = decode[ShuffleResultDTO](mix).right.get
      (m.votes, mix)
    }

    val parentHash = Crypto.sha512(parentStr)
    val expected = Statement.getMixStatement(mix, parentHash, configHash, item, auth)
    val expectedString = expected.asJson.noSpaces
    val publicKeyStr = ctx.section.getPublicKey(item).get

    if(expectedString == mixStmt) {
      logger.info(s"item $item processing mix $auth, statement OK")
      val authPk = Crypto.readPublicRsa(ctx.config.trustees(auth - 1))
      val ok = expected.verify(mixSig, authPk)
      if(ok) {
        logger.info(s"item $item processing mix $auth, signature OK")
        val pokOk = verifyShuffle(parentBallots, mix.votes, mix.shuffleProof,
          authPk.getModulus.toString, publicKeyStr, ctx.cSettings)

        logger.info(s"item $item processing mix $auth, pok $pokOk")
        if(pokOk) {
          val signature = expected.sign(ctx.trusteeCfg.privateKey)
          val file = IO.writeTemp(signature)
          ctx.section.addMixSignature(file, item, auth, ctx.position)
        } else {
          logger.error(s"item $item processing mix $auth, pok NOT ok")
          return Error(s"item $item processing mix $auth, pok NOT ok")
        }
      }
      else {
        logger.error(s"item $item processing mix $auth, signature NOT ok")
        return Error(s"item $item processing mix $auth, signature NOT ok")
      }
    } else {
      // the error will be caused below
      logger.error(s"item $item processing mix $auth, statement NOT ok")
      return Error(s"item $item processing mix $auth, statement NOT ok")
    }

    Ok
  }

  /** helper to verify a proof of shuffle */
  def verifyShuffle(parentVotes: Seq[String], shuffledVotes: Seq[String], shuffleProof: ShuffleProofDTO,
    proverId: String, publicKey: String, cSettings: CryptoSettings): Boolean = {

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val pk = keyPairGen.getPublicKeySpace().getElementFrom(publicKey)

    val shuffled = shuffledVotes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq
    val votes = parentVotes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v) ).seq

    Verifier.verifyShuffle(Util.tupleFromSeq(votes), Util.tupleFromSeq(shuffled), shuffleProof,
      proverId, pk, cSettings)
  }

  override def toString = s"VerifyMix($item, $auth)"
}

/** Add this authority's partial decryption of the output of the last mix.
 *
 *  This Action should be implemented carefully as privacy properties
 *  depend on decrypting ONLY those votes that have been mixed the
 *  required number of times by each of the authorities, in turn.
 *
 *  To do this, a validation chain is constructed based on checking for
 *  self signatures on previous mixes. These signatures ensure that
 *  each mix was executed by the correct authority and against the correct
 *  votes. By joining the assertions of each signed statements a
 *  chain is constructed whose elements assert the origin and destination of
 *  each mix. Only if the transitive chain yields a link between
 *  the ballot box votes (signed by the ballotbox), and the final mix
 *  votes, these votes are partially decrypted.
 *
 *  To partially decrypt, this authority retrieves its share and
 *  decrypts the private part using its master aes key.
 *
 */
case class AddDecryption(ctx: Context, item: Int) extends Action {
  val priority = 5

  def execute(): Result = {
    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"AddDecryption: invalid config")
    }

    // the chain is composed of elements of the from
    // input votes hash -> output votes hash
    // val chain = (1 to ctx.config.trustees.size).map { auth =>
    val chain = (1 to ctx.config.trustees.size).map { a =>

      // PERM
      val auth = Protocol.getMixPositionInverse(a, item, ctx.config.trustees.size)

      val mixStmtStr = ctx.section.getMixStatement(item, auth).get
      val mixStmt = decode[MixStatement](mixStmtStr).right.get
      val mixSig = ctx.section.getMixSignature(item, auth, ctx.position).get
      logger.info(s"checking mix self-signature on item $item auth $auth")
      val ok = mixStmt.verify(mixSig, ctx.trusteeCfg.publicKey)

      if(ok) {
        logger.info(s"mix self-signature on item $item auth $auth OK")
        mixStmt.parentHash -> mixStmt.mixHash
      }
      else {
        // will cause error below
        logger.warn(s"mix self-signature on item $item auth $auth NOT ok")
        "" -> ""
      }
    }.filter{ case(a, b) => a != ""}.toSet

    if(chain.size != ctx.config.trustees.size) {
      return Error(s"not enough elements in mix chain $chain")
    }
    logger.info(s"chain size on item $item OK")

    logger.info(s"obtaining transitive chain on item $item")
    val transitive = chain.reduceLeft{ (a,b) =>
      if(a._2 == b._1) {
        (a._1, b._2)
      }
      else {
        a
      }
    }

    // check the ballots-end of the chain
    val ballots = ctx.section.getBallots(item).get
    val ballotStmt = ctx.section.getBallotsStatement(item).get
    val ballotsSig = ctx.section.getBallotsSignature(item).get

    val expected = Statement.getBallotsStatement(transitive._1, configHash, item)
    val expectedString = expected.asJson.noSpaces
    val publicKey = Crypto.readPublicRsa(ctx.config.ballotbox)

    if(expectedString != ballotStmt) {
      logger.error(s"item $item ballot statements mismatch")
      return Error(s"item $item ballot statements mismatch")
    }
    logger.info(s"ballot statement on item $item OK")

    val ok = expected.verify(ballotsSig, publicKey)
    if(!ok) {
      logger.error(s"ballot signature on item $item NOT ok")
      return Error(s"ballot signature on item $item NOT ok")
    }
    logger.info(s"ballot signature on item $item OK")

    // check the mix-end of the chain
    // PERM
    val lastMixAuth = Protocol.getMixPositionInverse(item, ctx.config.trustees.size, ctx.config.trustees.size)
    // val mixStr = ctx.section.getMix(item, ctx.config.trustees.size).get
    val mixStr = ctx.section.getMix(item, lastMixAuth).get

    val mix = decode[ShuffleResultDTO](mixStr).right.get
    val mixHash = Crypto.sha512(mixStr)

    // the votes we will decrypt correspond to the end of the chain
    if(mixHash != transitive._2) {
      logger.error(s"last mix hash does not match chain-end on item $item")
      return Error(s"last mix hash does not match chain-end on item $item")
    }
    logger.info(s"transitive chain on item $item OK")

    val modulusStr = ctx.trusteeCfg.publicKey.getModulus.toString
    val share = ctx.section.getShare(item, ctx.position)
      .map(decode[Share](_).right.get).get

    logger.info(s"decrypting private share on item $item")

    val privateKey = Crypto.decryptAES(share.encryptedPrivateKey, ctx.trusteeCfg.aesKey)

    // create decryption
    val decryption = KeyMakerTrustee.partialDecryption(modulusStr, mix.votes, privateKey, ctx.cSettings)

    val statement = Statement.getDecryptionStatement(decryption, mixHash, configHash, item)
    val signature = statement.sign(ctx.trusteeCfg.privateKey)

    logger.info(s"adding decryptions on item $item")
    val file1 = IO.writeTemp(decryption.asJson.noSpaces)
    val file2 = IO.writeTemp(statement.asJson.noSpaces)
    val file3 = IO.writeTemp(signature)

    ctx.section.addDecryption(file1, file2, file3, item, ctx.position)

    Ok
  }

  override def toString = s"AddDecryption($item)"
}

/** Add the plaintexts, or signs them if we are not #1 authority.
 *
 *  Authority #1 is responsible for creating the plaintexts
 *  from the partial decryptions of each of the authorities. Once this
 *  has occured, the rest of authorities validate it by recreating the
 *  plaintexts themselves.
 *
 *  The public key is created and signed if
 *
 *  - the configuration is accepted
 *  - the decryptions have correct statements, signatures and pok
 *  - the number of decryptions is equal to number of authorities
 *
 *  Authorities other than #1 reuse the statement created by #1
 *  and sign it if everything is correct and the plaintexts are
 *  identical to their locally created ones.
 */
case class AddOrSignPlaintexts(ctx: Context, item: Int) extends Action {
  val priority = 6

  def execute(): Result = {
    val configHash = getValidConfigHash(ctx)
    if(configHash.length == 0) {
      logger.error(s"invalid config")
      return Error(s"AddOrSignPlaintexts: invalid config")
    }

    // get mixVotes
    // val mixStr = ctx.section.getMix(item, ctx.config.trustees.size).get
    // PERM
    val lastMixAuth = Protocol.getMixPositionInverse(item, ctx.config.trustees.size, ctx.config.trustees.size)
    val mixStr = ctx.section.getMix(item, lastMixAuth).get
    val mix = decode[ShuffleResultDTO](mixStr).right.get
    val mixHash = Crypto.sha512(mixStr)

    val collectedDecryptions = new ListBuffer[PartialDecryptionDTO]()

    // verify all shares
    (1 to ctx.config.trustees.size).map { auth =>

      logger.info(s"item $item processing decryption $auth..")
      val decryptionStr = ctx.section.getDecryption(item, auth).get
      val decryption = decode[PartialDecryptionDTO](decryptionStr).right.get
      val decryptionStmt = ctx.section.getDecryptionStatement(item, auth).get
      val decryptionSig = ctx.section.getDecryptionSignature(item, auth).get

      val expected = Statement.getDecryptionStatement(decryption, mixHash, configHash, item)
      val expectedString = expected.asJson.noSpaces
      val publicKeyStr = ctx.section.getPublicKey(item).get

      if(expectedString == decryptionStmt) {
        logger.info(s"item $item processing decryption $auth, statement OK")
        val authPk = Crypto.readPublicRsa(ctx.config.trustees(auth - 1))
        val modulusStr = authPk.getModulus.toString
        val ok = expected.verify(decryptionSig, authPk)
        if(ok && (mixHash == expected.mixHash)) {
          logger.info(s"item $item processing decryption $auth, signature OK")
          // logger.info("verifying decryption " + Crypto.sha512(decryption.asJson.noSpaces) + " with mod " + modulusStr + " votes " + Crypto.sha512(mix.votes.asJson.noSpaces))

          // FIXME should skip verifying pok on our own decryption
          val share = ctx.section.getShare(item, auth).map(decode[Share](_).right.get).get
          val pokOk = verifyDecryption(decryption, mix.votes, ctx.cSettings, modulusStr, share.share.keyShare)
          logger.info(s"item $item processing decryption $auth, pok $pokOk")
          if(pokOk) {
            collectedDecryptions += decryption
          }
          else {
            // the error will be caused below
            logger.warn(s"item $item processing decryption $auth, pok NOT ok")
          }
        }
      } else {
        // the error will be caused below
        logger.warn(s"item $item processing decryption $auth, statement NOT ok")
      }
    }

    if(collectedDecryptions.length == ctx.config.trustees.size) {

      val plaintextsSeq = combineDecryptions(collectedDecryptions, mix.votes, ctx.cSettings)
      val plaintexts = Plaintexts(plaintextsSeq).asJson.noSpaces
      val plaintextsHash = Crypto.sha512(plaintexts)
      val decryptionsHash = Crypto.sha512(collectedDecryptions.asJson.noSpaces)

      if(ctx.position == 1) {
        //  send and sign plaintexts
        val statement = Statement.getPlaintextsStatement(plaintextsHash, decryptionsHash, configHash, item)
        val signature = statement.sign(ctx.trusteeCfg.privateKey)

        val file1 = IO.writeTemp(plaintexts)
        val file2 = IO.writeTemp(statement.asJson.noSpaces)
        val file3 = IO.writeTemp(signature)

        logger.info(s"item $item adding plaintexts")
        ctx.section.addPlaintexts(file1, file2, file3, item, ctx.position)
      }
      else {
        // sign plaintexts if statements match
        val expected = Statement.getPlaintextsStatement(plaintextsHash, decryptionsHash, configHash, item)
        val expectedString = expected.asJson.noSpaces
        val ok = ctx.section.getPlaintextsStatement(item).map(expectedString == _).getOrElse(false)

        if(ok) {
          logger.info(s"item $item plaintexts statement OK")
          val sig = expected.sign(ctx.trusteeCfg.privateKey)
          val file1 = IO.writeTemp(sig)

          ctx.section.addPlaintextsSignature(file1, item, ctx.position)
        }
        else {
          logger.error(s"plaintexts statement mismatch")
          return Error(s"plaintexts statement mismatch")
        }
      }
    }
    else {
      logger.error(s"not enough decryptions collected ${collectedDecryptions.length}")
      return Error(s"not enough decryptions collected ${collectedDecryptions.length}")
    }

    Ok
  }

  /** helper to verify a decryption proof */
  def verifyDecryption(decryptions: PartialDecryptionDTO, mixedVotes: Seq[String],
    cSettings: CryptoSettings, proverId: String, publicKey: String): Boolean = {

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)
    val keyPairGen = elGamal.getKeyPairGenerator()
    val pk = keyPairGen.getPublicKeySpace().getElementFrom(publicKey)

    val votes = mixedVotes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v).asInstanceOf[Pair] ).seq

    Verifier.verifyPartialDecryption(decryptions, votes, cSettings,
      proverId, pk)
  }


  /** Helper to combine decryptions
   *
   *  combine the list of decryptions:
   *  obtain a^-x from individual a^-xi's (example below for n = 2)
   *
   *       === 1 === === 2 ===
   *  v1     a^xi      a^xi      = a^x
   *  v2     a^xi      a^xi      = a^x
   *  v3     a^xi      a^xi      = a^x
   *   .     a^xi      a^xi      = a^x
   *   .
   *
   */
  def combineDecryptions(decryptions: Seq[PartialDecryptionDTO], mixedVotes: Seq[String],
    cSettings: CryptoSettings) = {

    val decryptionElements = decryptions.map(
      ds => ds.partialDecryptions.par.map(Util.fromString(cSettings.group, _)).seq
    )

    val combined = decryptionElements.reduce { (a, b) =>
      (a zip b).par.map(c => c._1.apply(c._2)).seq
    }

    val elGamal = ElGamalEncryptionScheme.getInstance(cSettings.generator)

    val votes = mixedVotes.par.map( v => Util.fromString(elGamal.getEncryptionSpace, v).asInstanceOf[Pair] ).seq
    // a^-x * b = m
    val decrypted = (votes zip combined).par.map(c => c._1.getSecond().apply(c._2)).seq
    val encoder = ZModPrimeToGStarModSafePrime.getInstance(cSettings.group)

    val plaintexts = decrypted.par.map(encoder.decode(_).convertToString).seq
    plaintexts
  }

  override def toString = s"AddOrSignPlaintexts($item)"
}