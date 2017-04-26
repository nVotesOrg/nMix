package org.nvotes.trustee

import ch.bfh.unicrypt.crypto.keygenerator.interfaces.KeyPairGenerator
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime
import ch.bfh.unicrypt.crypto.encoder.classes.ZModPrimeToGStarModSafePrime
import java.math.BigInteger

import org.scalatest.FlatSpec
import org.nvotes.libmix._

/** Tests libmix functionality
 *
 *  This test is a duplicate of the libmix CryptoSpec. It is added
 *  here for convenience.
 */
class LibmixSpec extends FlatSpec {

  val grp = GStarModSafePrime.getFirstInstance(2048)

  val gen = grp.getDefaultGenerator()
  val Csettings = CryptoSettings(grp, gen)

  val shares = scala.collection.mutable.ArrayBuffer.empty[Element[_]]
  val privates = scala.collection.mutable.ArrayBuffer.empty[Element[_]]

  object KM extends KeyMaker
  object MX extends Mixer

  "The shuffle process" should "verify ok and decrypt correctly" in {
    val elGamal = ElGamalEncryptionScheme.getInstance(Csettings.generator)
    val keyPair = elGamal.getKeyPairGenerator().generateKeyPair()
    val privateKey = keyPair.getFirst()
    val publicKey = keyPair.getSecond()

    val plaintexts = Seq.fill(10)(scala.util.Random.nextInt(10))
    val votes = Util.encryptVotes(plaintexts, Csettings, publicKey)

    val shuffleResult = MX.shuffle(Util.tupleFromSeq(votes), publicKey, Csettings, "proverId")
    val shuffled = shuffleResult.votes.map( v => Util.fromString(elGamal.getEncryptionSpace, v) )

    val verified = Verifier.verifyShuffle(Util.tupleFromSeq(votes), Util.tupleFromSeq(shuffled),
      shuffleResult.shuffleProof, "proverId", publicKey, Csettings)

    assert(verified)

    val encoder = ZModPrimeToGStarModSafePrime.getInstance(Csettings.group)
    val decrypted = shuffled.map { v =>
      encoder.decode(elGamal.decrypt(privateKey, v)).convertToString
    }

    assert(plaintexts.sorted == decrypted.map(_.toInt).sorted)
  }

  "The dkg process" should "verify shares, verify decryptions, decrypt correctly" in {
    val (share, key) = KM.createShare("1", Csettings)
    var ok = addShare(share, "1", Csettings, key.convertToString)
    assert(ok)

    val (share2, key2) = KM.createShare("2", Csettings)
    ok = addShare(share2, "2", Csettings, key2.convertToString)
    assert(ok)

    val publicKey = combineShares(shares, Csettings)

    val plaintexts = Seq.fill(10)(scala.util.Random.nextInt(10))
    val ciphertexts = Util.encryptVotes(plaintexts, Csettings, publicKey)

    // a^-x1
    val elementsOne = KM.partialDecrypt(ciphertexts, privates(0), "0", Csettings)
    ok = Verifier.verifyPartialDecryption(elementsOne, ciphertexts, Csettings, "0", shares(0))
    assert(ok)
    // a^-x2
    val elementsTwo = KM.partialDecrypt(ciphertexts, privates(1), "1", Csettings)
    ok = Verifier.verifyPartialDecryption(elementsTwo, ciphertexts, Csettings, "1", shares(1))
    assert(ok)

    // a^-x = a^-x1 * a^-x2 ...
    val combined = (elementsOne.partialDecryptions.map(Csettings.group.getElementFrom(_))
      zip elementsTwo.partialDecryptions.map(Csettings.group.getElementFrom(_))).map(c => c._1.apply(c._2))

    // a^-x * b = m
    val decrypted = (ciphertexts zip combined).map(c => c._1.getSecond().apply(c._2))
    val encoder = ZModPrimeToGStarModSafePrime.getInstance(Csettings.group)
  val decoded = decrypted.map(encoder.decode(_).convertToString)

    assert(plaintexts.sorted == decoded.map(_.toInt).sorted)
  }

  def combineShares(shares: Seq[Element[_]], Csettings: CryptoSettings) = {
    var encKey = Csettings.group.getIdentityElement()

    // y = y1 * y2 * y3....
    for (keyShare <- shares) {
      encKey = encKey.apply(keyShare)
    }

    encKey
  }

  def addShare(encryptionKeyShare: EncryptionKeyShareDTO, proverId: String, CSettings: CryptoSettings, privateK: String) = {
    val result = Verifier.verifyKeyShare(encryptionKeyShare, Csettings, proverId: String)
    if(result) {
      val elGamal = ElGamalEncryptionScheme.getInstance(Csettings.generator)
      val keyPairGen: KeyPairGenerator = elGamal.getKeyPairGenerator()
      val publicKey = keyPairGen.getPublicKeySpace().getElementFrom(encryptionKeyShare.keyShare)
      shares += publicKey
      val privateKey = keyPairGen.getPrivateKeySpace().getElementFrom(privateK)

      privates += privateKey
    }

    result
  }
}