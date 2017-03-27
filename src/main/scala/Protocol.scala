package org.nvotes.trustee

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime
import org.nvotes.libmix._

import java.nio.charset.StandardCharsets
import scala.collection.mutable.ListBuffer

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/** The configuration for a protocol run, typically for an election
 *
 *  Some of these are parameterized by authority and item, needing
 *  methods.
 *
 *  The trustees and ballotbox field are public keys. They must be formatted without
 *  spaces, using \n as markers for newlines. Read by Crypto.ReadPublicRSA
 *  (sublime -> replace \n with \\n)
 */
case class Config(id: String, name: String, bits: Int, items: Int, ballotbox: String, trustees: Array[String]) {
  override def toString() = s"Config($id $name $bits $items)"
}

/** A share of the distributed key.
 *
 *  The public part is stored as an nMix EncryptionKeyShareDTO , which
 *  contains the share and the proof of knowledge.
 *
 *  The private part is aes encrypted by the authority.
 *
 */
case class Share(share: EncryptionKeyShareDTO, encryptedPrivateKey: String)

/** Ballots provided by the ballotbox in unicrypt format. Encrypted */
case class Ballots(ballots: Seq[String])

/** Plaintexts jointly encrypted by authorities after mixing, in unicrypt format */
case class Plaintexts(plaintexts: Seq[String])

/** Convenience class to pass around relevant data  */
case class Context(config: Config, section: BoardSection, trusteeCfg: TrusteeConfig,
  position: Int, cSettings: CryptoSettings)

/** Implements the cryptographic protocol through stateless, reactive and
 *  choreographed actors.
 *
 *  At a high level the steps are
 *
 *  1. Public key generation
 *  2. Ballot casting (provided externally)
 *  3. Mixing
 *  4. Joint decryption
 *
 *  The protocol is implemented with rules of the form
 *
 *    Condition => Action
 *
 *  which operate on bulletin board data.
 *
 *  Because actors are stateless, Actions are responsible
 *  for verifying correctness of the execution by validating
 *  the bulletin board data from scratch at each execution.
 */
object Protocol extends Names {

  val logger = LoggerFactory.getLogger(Protocol.getClass)

  /** Executes one run of the protocol rules for one board section
   *
   *  The bulletin board is first updated (sync). Then rules are then evaluated against
   *  the updated data.
   *
   *  Global rules depend on data that is global to the section
   *  Item rules depend only on item data
   */
  def execute(section: BoardSection, trusteeCfg: TrusteeConfig): Unit = {

    logger.info(s"Begin executing protocol for section '${section.name}'")
    logger.info(s"Syncing...'${section.name}'")

    section.sync()
    val files = section.getFileSet

    if(!files.contains(CONFIG)) {
      logger.error(s"Section ${section.name} does not have a config")
      // FIXME cause a real error
      return
    }

    val configString = section.getConfig.get
    val config = decode[Config](configString).right.get
    logger.info(s"Found config: $config")
    val position = getMyPosition(config, trusteeCfg)

    if(position == 0) {
      logger.info(s"could not find self in list of trustees for config $config")
      // FIXME cause a real error
      return
    }

    // FIXME this info should be in config, not just the bits
    val group = GStarModSafePrime.getFirstInstance(config.bits)
    val generator = group.getDefaultGenerator()
    val cSettings = CryptoSettings(group, generator)

    val ctx = Context(config, section, trusteeCfg, position, cSettings)

    val rules = globalRules(ctx)

    // first rule that matches is executed
    val hit = rules.find{ case (c, a) =>
      c.eval(files)
    }.map(_._2)

    logger.info(s"* Global matches: $hit")
    val result = hit.map(_.execute()).getOrElse(Ok)
    if(hit.size > 0) logger.info(s"* Global rules result: $result")

    if(result != Ok) {
      logger.warn(s"Got pause or error signal: $result")
      return
    }

    val items = config.items

    val irules = (1 to items).map(i => itemRules(ctx, i, files))

    // get first rule that matches for each item, then
    // collect Action's into list and sort them by priority
    val hits = irules.flatMap { rules =>
      rules.find{ case (c, a) =>
        c.eval(files)
      }.map(_._2)
    }.sorted

    if(hits.size > 0) {
      logger.info(s"Per-item hits: ************************")
      logger.info(s"${hits.map(_.toString)}")
      logger.info(s"***************************************")

      val results = hits.map(action => action -> action.execute)
      logger.info(s"Per-item results: *********************")
      logger.info(s"$results")
      logger.info(s"***************************************")
    }
    else {
      logger.info(s"* Per-item matches: None")
    }
  }

  /** Returns the global rules.
   *
   *  Examples of global rules are
   *
   *  1) Stop execution if a pause is requested
   *  2) Stop execution if any authority has reported an error
   *  3) Validate the global config if this authority has not yet done so
   *
   *  A list of rules has type List[(Cond, Action)]
   */
  private def globalRules(ctx: Context) = {

    val pauseYes = Condition.yes(PAUSE)
    val errorsYes = Condition((1 to ctx.config.items).map(i => ERROR(i) -> false).toList).no(ERROR).neg
    val configNo = Condition.yes(CONFIG).yes(CONFIG_STMT).no(CONFIG_SIG(ctx.position))

    ListBuffer[(Cond, Action)](
      pauseYes -> StopAction("pause found"),
      errorsYes -> StopAction("error found"),
      configNo -> ValidateConfig(ctx)
    )
  }

  /** Returns the per-item rules.
   *
   *  Per-item rules implement the core of the crypto protocol.
   *
   *  A list of rules has type List[(Cond, Action)]
   */
  private def itemRules(ctx: Context, item: Int, files: Set[String]) = {

    val config = ctx.config

    val allConfigsYes = Condition(
      (1 to config.trustees.size).map(auth => CONFIG_SIG(auth) -> true)
      .toList
    )

    val myShareNo = Condition.no(SHARE(item, ctx.position)).no(SHARE_STMT(item, ctx.position))
      .no(SHARE_SIG(item, ctx.position))

    val rules = ListBuffer[(Cond, Action)](
      allConfigsYes.and(myShareNo) -> AddShare(ctx, item)
    )

    val allShares = Condition((1 to config.trustees.size).flatMap { auth =>
        List(SHARE(item, auth) -> true, SHARE_STMT(item, auth) -> true, SHARE_SIG(item, auth) -> true)
      }
      .toList
    )

    if(ctx.position == 1) {
      val noPublicKey = Condition.no(PUBLIC_KEY(item))
      rules += allShares.and(noPublicKey) -> AddOrSignPublicKey(ctx, item)
    }

    val noPublicKeySig = Condition.yes(PUBLIC_KEY(item)).no(PUBLIC_KEY_SIG(item, ctx.position))
    rules += allShares.and(noPublicKeySig) -> AddOrSignPublicKey(ctx, item)


    /*val previousMixesYes = Condition((1 to ctx.position - 1).flatMap { auth =>
        List(MIX(item, auth) -> true, MIX_STMT(item, auth) -> true, MIX_SIG(item, auth, auth) -> true)
      }
      .toList
    )*/
    // PERM
    val myMixPosition = getMixPosition(ctx.position, item, ctx.config.trustees.size)
    val previousMixesYes = Condition((1 to myMixPosition - 1).flatMap { auth =>
        val mixAuth = getMixPositionInverse(auth, item, ctx.config.trustees.size)
        List(MIX(item, mixAuth) -> true, MIX_STMT(item, mixAuth) -> true, MIX_SIG(item, mixAuth, mixAuth) -> true)
      }
      .toList
    )

    val ballotsYes = Condition.yes(BALLOTS(item)).yes(BALLOTS_STMT(item)).yes(BALLOTS_SIG(item))

    val myMixNo = ballotsYes.and(previousMixesYes).andNot(MIX(item, ctx.position))
    rules += myMixNo -> AddMix(ctx, item)

    // sign mixes other than our own
    val missingSigs = (1 to config.trustees.size).filter(_ != ctx.position).map { auth =>
      (auth, item, Condition(List(MIX(item, auth) -> true, MIX_STMT(item, auth) -> true,
        MIX_SIG(item, auth, auth) -> true, MIX_SIG(item, auth, ctx.position) -> false)))
    }

    missingSigs.foreach { case(auth, item, noMixSig) =>
      rules += noMixSig -> VerifyMix(ctx, item, auth)
    }

    val allMixSigs = Condition((1 to config.trustees.size).map { auth =>
      MIX_SIG(item, auth, ctx.position) -> true
    }.toList)

    val noDecryptions = Condition.no(DECRYPTION(item, ctx.position))
      .no(DECRYPTION_STMT(item, ctx.position)).no(DECRYPTION_SIG(item, ctx.position))

    rules += allMixSigs.and(noDecryptions) -> AddDecryption(ctx, item)

    val allDecryptions = Condition((1 to config.trustees.size).flatMap { auth =>
        List(DECRYPTION(item, auth) -> true, DECRYPTION_STMT(item, auth) -> true,
          DECRYPTION_SIG(item, auth) -> true)
      }
      .toList
    )

    if(ctx.position == 1) {
      val noPlaintexts = Condition.no(PLAINTEXTS(item))
      rules += allDecryptions.and(noPlaintexts) -> AddOrSignPlaintexts(ctx, item)
    }

    val noPlaintextsSig = Condition.yes(PLAINTEXTS(item)).no(PLAINTEXTS_SIG(item, ctx.position))
    rules += allDecryptions.and(noPlaintextsSig) -> AddOrSignPlaintexts(ctx, item)

    rules
  }


  /** Returns the position of the trustee for the given config.
   *
   *  Positions start at 1. If the trustee is not found, returns 0.
   */
  private def getMyPosition(config: Config, trusteeConfig: TrusteeConfig): Int = {
    val pks = config.trustees.map(Crypto.readPublicRsa(_))
    pks.indexOf(trusteeConfig.publicKey) + 1
  }

  /** Returns the permuted mix position of the trustee for the given config.
   *
   *  Positions start at 1.
   *
   *  Examples
   *
   *  123 at item 1 => 123
   *  123 at item 2 => 231
   *  123 at item 3 => 312
   *  123 at item 4 => 123
   *
   *  The permutation is a 1 shift left permutation
   *
   *  This 1-shift left is a generator of a cyclic permutation group of
   *  order 'trustees'
   *
   */
  def getMixPosition(auth: Int, item: Int, trustees: Int): Int = {
    val permuted = (auth + (item - 1)) % trustees
    permuted + 1
  }

  /** Returns the inverse of the permuted mix position
   *
   *  See above.
   */
  def getMixPositionInverse(auth: Int, item: Int, trustees: Int): Int = {
    /** for a cyclic group with generator g of order n we have
     *
     * g^n = 1
     *
     * applying g to some power p we have
     *
     * g^p = x
     *
     * since
     *
     * g^p * g^(n-p) = g^n = 1
     *
     * the inverse of x=g^p is g^(n-p)
     *
     * n-p is the "gap" below, and (item - 1) is p
     *
     */
    val gap = trustees - (item - 1)

    val permuted = (auth + gap) % trustees
    permuted + 1
  }
}

sealed trait Result
/** continue execution */
case object Ok extends Result
/** should stop execution for this section */
case class Stop(message: String) extends Result
/** should stop execution and write error to the section */
case class Error(message: String) extends Result