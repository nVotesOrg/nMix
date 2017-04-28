package org.nvotes.trustee

import java.nio.file.Paths
import java.nio.file.Path
import java.nio.file.Files
import java.net.URI

import org.scalatest.FlatSpec
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Tests the protocol using an in memory bulletin board
 *
 */
class ProtocolSpec extends FlatSpec with Names {

  "Protocol" should "return error if no config" in {
    val auth1cfg = getCfg1
    val auth2cfg = getCfg2
    val bb = new MemoryBoardSection("test")

    val result1 = Protocol.execute(bb, auth1cfg)
    val result2 = Protocol.execute(bb, auth2cfg)

    assert(result1.isInstanceOf[Error])
    assert(result2.isInstanceOf[Error])
  }

  "Protocol" should "cause signatures for config" in {
    val auth1cfg = getCfg1
    val auth2cfg = getCfg2
    val bb = new MemoryBoardSection("test")
    bb.addConfig(config, configStatement)


    val result1 = Protocol.execute(bb, auth1cfg)
    val result2 = Protocol.execute(bb, auth2cfg)

    val files = bb.getFileSet
    assert(files.contains(CONFIG_SIG(1)))
    assert(files.contains(CONFIG_SIG(2)))
  }

  def getCfg1 = {
    TrusteeConfig(bogusPath, bogusUri, bogusUri, auth1pubRsa, auth1privRsa, aesKey, peers)
  }

  def getCfg2 = {
    TrusteeConfig(bogusPath, bogusUri, bogusUri, auth2pubRsa, auth2privRsa, aesKey, peers)
  }

  val auth1pub = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzDavZyxk38eTbilzTena\nB5xEqCMGyKgT3/cJ3gUWxFli/aTh3Rs5gjd5PKf/aefljBVcR8OsDTKxeBT6DXT9\nwdbPaGtF9nG0+Wi8KtQ15SiZdg72KX+NMGx6HVuqWZvojxRRmPCDar8oSFrcRIuV\ndimOCvmKQAjUaG9j2ZXfbcA0l9QA1nMTG/3BL/VFmBeCdiSyROjtmpCKgCgeb2HH\nfNA/E/FUipOT7fLzWFVohnzSY65gjkG3U2h1vEHwzqkWVo4vuOXX/WZcRmrIlQDq\njAwG6piiNHhUmxAk5/2LWaZL2mfVV4peXpHjEUrCSe/DSkuMraac6lYMshWXfDQc\nsos9CxdbaBHxvvzRH+ja0Wt+QSAooQMVXX+fFQrJUCK2TTIWZKfFQR2Js1XfhfE4\n3Mn1l/TKQadq2a3F50gAy5JrXDPc9LcSzRexwIfUMzjQ7QvIWsmmShD9rwnWuAti\nwWWxG0ReB7d6qUkZGCtzoYNb9BqKEI39lScMhfY+wfAN4d7Mi6EcD1yPra8sOqR1\n04cyH5dn3DUZtHzZF9EWx5BPPhyYxI40DFXFn2UAb1bb/R89YuFcKyxgyrZjPlHe\nv5UnfA0XsbfUPiBVz7cEuf23R7sgxYJJSyZaf5Yqw4bOoYELAGokppA3yPc+6pNN\n8lp0ycZbowlpSz+SAXMFFdsCAwEAAQ==\n-----END PUBLIC KEY-----"
  val auth2pub = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2PfFrJXJ3w9PdFaffP7f\nQDqyxQFbSaJKT3I2tzxKnLR4w/nb0Dl/aQuAmuK0AJ3iF33tBH2Gy8md64QXzB4V\nlsktz2GzL+FCyl8ZgOkHAh6+H7pkpbGeFL4vLcv8TD+DRZ1/EWU2knKC4+eF92YY\nC5+Zp0zxc+MGTZreT4kULT7TW8vcP+l65fgpZEOMHS5FGMzuI6a18rgBLOyEcjzm\nJxALNgtdXXtowWhwKQ0BpPY++57aKiXX7Z4FLjmiHespk02pjoS5mWsMeL1DfeOr\nDH3PTF6J8aef1Q3n2QjubpUnBB+2z0bwCYZUXYMwNtfk1mE6o568ijXAYnW0Mcr5\noma7FsiHo3HYX6xJ8Nh5P7f23Yd94KvOePys8gKzFuv0yDma1bm9jtXeEIt7HV04\nbTfj1mmBWQcwRyOrk8qKgQWD9LlwHJq//cAyo13JsII7saNjwTSFVfLl5LgAJhDM\nHtfQGEFxUZa6tXY0Y+anCOnQvUXgDIK5j8d4qODLvGA3fWD5i0UiaOtY/yM+Olsf\nQ+doqdeC2q++1gXvN0MKMGxQSog5MyRADzsnILn3sCI6KoicTxFuvdfc56GsepnC\nBO/cxzGM4FrZ2pSvrmNh7soH+0beqnNCYt0dIXkI3wzDl9d11uGT7PPzU4Kx8fBr\n5/7CxKLYr8tGDCPhTY3KCfUCAwEAAQ==\n-----END PUBLIC KEY-----"
  val auth1priv = "-----BEGIN PRIVATE KEY-----\n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\nNg/zknYLjgyJ9MeJ3AE5aAiWeFiDhZE=\n-----END PRIVATE KEY-----"
  val auth2priv = "-----BEGIN PRIVATE KEY-----\n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\nuhiDkrXt5KKS5LED40dXYzY32RYcJA==\n-----END PRIVATE KEY-----"
  val ballotboxpub = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxR1ONgU7Uax+0Sp50zLD\njCkHxvxIU4WPk8EWJaZDJcq5LZqOqXT9vBoutOd6uuajLi590vt6Lmb9hqn79Otj\nqov58Xg/BUDTf3RFLeyIn4+x4+j7W5GlIrmGaqNg7EalCacsemqmcbuFrRnMA6g7\n62n0zVS61BX+tpVH5HkBXWwI+HIU1bEBHiUlQQN12QeNxW7tcdrC+JSUyc+vqb2z\niUVrbd0X9dEfppc5EPhBGBQ6haFcYd6nX788tiVAW4eaAJFVgJXOtVVqBSuMba6M\nDlj2SO+oEMgx4lEunH2mPmjx/7kFOLCfRWdGpNIrjAG4yyni2Q0wcZYtJbYo1jfr\nzidWkqBHxMUVM/tQnbxrx+KpEXUJGytUanTzNyKJebCkqxSG3WbblD3IKYz6Lw1v\nUFekjikyAnNTWakmPAhxeVCf1pksEiS388sfomMiC6IIO8Fb+25mSTj+qSETd4fQ\n+j+xghQvMs6Cmtf4iQhlHzFqsHG2EmP1YfVlWFFqauyM9eBjWCccMKTxKXaMSzc0\nnrDkdIirdH2sryDLMYh8ZaGYJqPyg2Fyv7ZuLKUmdJYYxloFGNJLYpJ2JejbQ+Dt\n0VN/oA7KLk31qkd5Cv/jf1RJOFoKmKoKS+M5vSzKVF0Upc9AU+Jrv0BXQbe/nk72\ni1mZeW4V8w/DrqiOXLH2mskCAwEAAQ==\n-----END PUBLIC KEY-----"

  val auth1pubRsa = Crypto.readPublicRsa(auth1pub)
  val auth2pubRsa = Crypto.readPublicRsa(auth2pub)
  val auth1privRsa = Crypto.readPrivateRsa(auth1priv)
  val auth2privRsa = Crypto.readPrivateRsa(auth2priv)
  val ballotboxpubRsa = Crypto.readPublicRsa(ballotboxpub)
  val aesKey = Crypto.randomAESKeyElement
  val peers = Array(auth1pubRsa, auth2pubRsa, ballotboxpubRsa)
  val bogusPath = Paths.get("foobar")
  val bogusUri = new URI("foobar")

  val config = """{"id":"28222807-3189-46c9-9393-0fb3da5fdf5c","name":"e1","modulus":"16158503035655503650357438344334975980222051334857742016065172713762327569433945446598600705761456731844358980460949009747059779575245460547544076193224141560315438683650498045875098875194826053398028819192033784138396109321309878080919047169238085235290822926018152521443787945770532904303776199561965192760957166694834171210342487393282284747428088017663161029038902829665513096354230157075129296432088558362971801859230928678799175576150822952201848806616643615613562842355410104862578550863465661734839271290328348967522998634176499319107762583194718667771801067716614802322659239302476074096777926805529798824879","generator":"4","items":3,"ballotbox":"-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxR1ONgU7Uax+0Sp50zLD\njCkHxvxIU4WPk8EWJaZDJcq5LZqOqXT9vBoutOd6uuajLi590vt6Lmb9hqn79Otj\nqov58Xg/BUDTf3RFLeyIn4+x4+j7W5GlIrmGaqNg7EalCacsemqmcbuFrRnMA6g7\n62n0zVS61BX+tpVH5HkBXWwI+HIU1bEBHiUlQQN12QeNxW7tcdrC+JSUyc+vqb2z\niUVrbd0X9dEfppc5EPhBGBQ6haFcYd6nX788tiVAW4eaAJFVgJXOtVVqBSuMba6M\nDlj2SO+oEMgx4lEunH2mPmjx/7kFOLCfRWdGpNIrjAG4yyni2Q0wcZYtJbYo1jfr\nzidWkqBHxMUVM/tQnbxrx+KpEXUJGytUanTzNyKJebCkqxSG3WbblD3IKYz6Lw1v\nUFekjikyAnNTWakmPAhxeVCf1pksEiS388sfomMiC6IIO8Fb+25mSTj+qSETd4fQ\n+j+xghQvMs6Cmtf4iQhlHzFqsHG2EmP1YfVlWFFqauyM9eBjWCccMKTxKXaMSzc0\nnrDkdIirdH2sryDLMYh8ZaGYJqPyg2Fyv7ZuLKUmdJYYxloFGNJLYpJ2JejbQ+Dt\n0VN/oA7KLk31qkd5Cv/jf1RJOFoKmKoKS+M5vSzKVF0Upc9AU+Jrv0BXQbe/nk72\ni1mZeW4V8w/DrqiOXLH2mskCAwEAAQ==\n-----END PUBLIC KEY-----\n","trustees":["-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzDavZyxk38eTbilzTena\nB5xEqCMGyKgT3/cJ3gUWxFli/aTh3Rs5gjd5PKf/aefljBVcR8OsDTKxeBT6DXT9\nwdbPaGtF9nG0+Wi8KtQ15SiZdg72KX+NMGx6HVuqWZvojxRRmPCDar8oSFrcRIuV\ndimOCvmKQAjUaG9j2ZXfbcA0l9QA1nMTG/3BL/VFmBeCdiSyROjtmpCKgCgeb2HH\nfNA/E/FUipOT7fLzWFVohnzSY65gjkG3U2h1vEHwzqkWVo4vuOXX/WZcRmrIlQDq\njAwG6piiNHhUmxAk5/2LWaZL2mfVV4peXpHjEUrCSe/DSkuMraac6lYMshWXfDQc\nsos9CxdbaBHxvvzRH+ja0Wt+QSAooQMVXX+fFQrJUCK2TTIWZKfFQR2Js1XfhfE4\n3Mn1l/TKQadq2a3F50gAy5JrXDPc9LcSzRexwIfUMzjQ7QvIWsmmShD9rwnWuAti\nwWWxG0ReB7d6qUkZGCtzoYNb9BqKEI39lScMhfY+wfAN4d7Mi6EcD1yPra8sOqR1\n04cyH5dn3DUZtHzZF9EWx5BPPhyYxI40DFXFn2UAb1bb/R89YuFcKyxgyrZjPlHe\nv5UnfA0XsbfUPiBVz7cEuf23R7sgxYJJSyZaf5Yqw4bOoYELAGokppA3yPc+6pNN\n8lp0ycZbowlpSz+SAXMFFdsCAwEAAQ==\n-----END PUBLIC KEY-----","\n-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2PfFrJXJ3w9PdFaffP7f\nQDqyxQFbSaJKT3I2tzxKnLR4w/nb0Dl/aQuAmuK0AJ3iF33tBH2Gy8md64QXzB4V\nlsktz2GzL+FCyl8ZgOkHAh6+H7pkpbGeFL4vLcv8TD+DRZ1/EWU2knKC4+eF92YY\nC5+Zp0zxc+MGTZreT4kULT7TW8vcP+l65fgpZEOMHS5FGMzuI6a18rgBLOyEcjzm\nJxALNgtdXXtowWhwKQ0BpPY++57aKiXX7Z4FLjmiHespk02pjoS5mWsMeL1DfeOr\nDH3PTF6J8aef1Q3n2QjubpUnBB+2z0bwCYZUXYMwNtfk1mE6o568ijXAYnW0Mcr5\noma7FsiHo3HYX6xJ8Nh5P7f23Yd94KvOePys8gKzFuv0yDma1bm9jtXeEIt7HV04\nbTfj1mmBWQcwRyOrk8qKgQWD9LlwHJq//cAyo13JsII7saNjwTSFVfLl5LgAJhDM\nHtfQGEFxUZa6tXY0Y+anCOnQvUXgDIK5j8d4qODLvGA3fWD5i0UiaOtY/yM+Olsf\nQ+doqdeC2q++1gXvN0MKMGxQSog5MyRADzsnILn3sCI6KoicTxFuvdfc56GsepnC\nBO/cxzGM4FrZ2pSvrmNh7soH+0beqnNCYt0dIXkI3wzDl9d11uGT7PPzU4Kx8fBr\n5/7CxKLYr8tGDCPhTY3KCfUCAwEAAQ==\n-----END PUBLIC KEY-----"]}"""
  val configStatement = """{"configHash":"EFF86B73B1A046EE45B6F18E23B0EE98C6E4CF845C6B9ABEF7A3A72A083BAF9FCC6D6F8AEB321A08FCB53B13117466FCB4D32EE5FD284A020023DAF094BE1BBB"}"""
}

/** An in memory implementation of a bulletin board section
 *
 *  This is only meant to be used for the test above
 */
case class MemoryBoardSection(name: String) extends BoardSectionInterface with Names {
  import scala.collection.mutable.Map

  val contents = Map[String, Array[Byte]]()
  val preShuffleData = Map[String, PreShuffleData]()

  def addConfig(config: String, configStatement: String) = {
    contents += CONFIG -> config.getBytes(StandardCharsets.UTF_8)
    contents += CONFIG_STMT -> configStatement.getBytes(StandardCharsets.UTF_8)
  }

  def getFileSet: Set[String] = synchronized {
    contents.keySet.toSet ++ preShuffleData.keySet
  }

  def addError(error: Path, position: Int): Unit = synchronized {
    add(error, ERROR(position))
  }

  def getConfig: Option[String] = contents.get(CONFIG).map(str(_))

  def getConfigStatement: Option[String] = contents.get(CONFIG_STMT).map(str(_))

  def getConfigSignature(auth: Int): Option[Array[Byte]] = {
    contents.get(CONFIG_SIG(auth))
  }

  def addConfig(config: Path): Unit = synchronized {
    add(config, CONFIG)
  }

  def addConfigSig(sig: Path, position: Int): Unit = synchronized {
    add(sig, CONFIG_SIG(position))
  }

  def addShare(share: Path, stmt: Path, sig: Path, item: Int, position: Int): Unit = synchronized {
    add(share, SHARE(item, position))
    add(stmt, SHARE_STMT(item, position))
    add(sig, SHARE_SIG(item, position))
  }

  def getShare(item: Int, auth: Int): Option[String] = {
    contents.get(SHARE(item, auth)).map(str(_))
  }

  def getShareStatement(item: Int, auth: Int): Option[String] = {
    contents.get(SHARE_STMT(item, auth)).map(str(_))
  }

  def getShareSignature(item: Int, auth: Int): Option[Array[Byte]] = {
    contents.get(SHARE_SIG(item, auth))
  }

  def addPublicKey(publicKey: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    add(publicKey, PUBLIC_KEY(item))
    add(stmt, PUBLIC_KEY_STMT(item))
    add(sig, PUBLIC_KEY_SIG(item, auth))
  }

  def addPublicKeySignature(sig: Path, item: Int, auth: Int): Unit = synchronized {
    add(sig, PUBLIC_KEY_SIG(item, auth))
  }

  def getPublicKey(item: Int): Option[String] = {
    contents.get(PUBLIC_KEY(item)).map(str(_))
  }

  def getPublicKeyStatement(item: Int): Option[String] = {
    contents.get(PUBLIC_KEY_STMT(item)).map(str(_))
  }

  def getPublicKeySignature(item: Int, auth: Int): Option[Array[Byte]] = {
    contents.get(PUBLIC_KEY_SIG(item, auth))
  }

  def getBallots(item: Int): Option[String] =  {
    contents.get(BALLOTS(item)).map(str(_))
  }

  def getBallotsStatement(item: Int): Option[String] =  {
    contents.get(BALLOTS_STMT(item)).map(str(_))
  }

  def getBallotsSignature(item: Int): Option[Array[Byte]] =  {
    contents.get(BALLOTS_SIG(item))
  }

  def addBallots(ballots: Path, stmt: Path, sig: Path, item: Int): Unit = synchronized {
    add(ballots, BALLOTS(item))
    add(stmt, BALLOTS_STMT(item))
    add(sig, BALLOTS_SIG(item))
  }

  def getPreShuffleDataLocal(item: Int, auth: Int): Option[PreShuffleData] = synchronized {
    preShuffleData.get(PERM_DATA(item, auth))
  }

  def addPreShuffleDataLocal(data: PreShuffleData, item: Int, auth: Int) = synchronized {
    preShuffleData += PERM_DATA(item, auth) -> data
  }

  def rmPreShuffleDataLocal(item: Int, auth: Int) = synchronized {
    preShuffleData -= PERM_DATA(item, auth)
  }

  def getMix(item: Int, auth: Int): Option[String] =  {
    contents.get(MIX(item, auth)).map(str(_))
  }

  def getMixStatement(item: Int, auth: Int): Option[String] = {
    contents.get(MIX_STMT(item, auth)).map(str(_))
  }

  def getMixSignature(item: Int, auth: Int, auth2: Int): Option[Array[Byte]] = {
    contents.get(MIX_SIG(item, auth, auth2))
  }

  def addMix(mix: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    add(mix, MIX(item, auth))
    add(stmt, MIX_STMT(item, auth))
    add(sig, MIX_SIG(item, auth, auth))
  }

  def addMixSignature(sig: Path, item: Int, authMixer: Int, authSigner: Int): Unit = synchronized {
    add(sig, MIX_SIG(item, authMixer, authSigner))
  }

  def getDecryption(item: Int, auth: Int): Option[String] = {
    contents.get(DECRYPTION(item, auth)).map(str(_))
  }

  def getDecryptionStatement(item: Int, auth: Int): Option[String] = {
    contents.get(DECRYPTION_STMT(item, auth)).map(str(_))
  }

  def getDecryptionSignature(item: Int, auth: Int): Option[Array[Byte]] = {
    contents.get(DECRYPTION_SIG(item, auth))
  }

  def addDecryption(decryption: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    add(decryption, DECRYPTION(item, auth))
    add(stmt, DECRYPTION_STMT(item, auth))
    add(sig, DECRYPTION_SIG(item, auth))
  }

  def getPlaintexts(item: Int): Option[String] = {
    contents.get(PLAINTEXTS(item)).map(str(_))
  }

  def getPlaintextsStatement(item: Int): Option[String] = {
    contents.get(PLAINTEXTS_STMT(item)).map(str(_))
  }

  def getPlaintextsSignature(item: Int, auth: Int): Option[Array[Byte]] = {
    contents.get(PLAINTEXTS_SIG(item, auth))
  }

  def addPlaintexts(plaintexts: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    add(plaintexts, PLAINTEXTS(item))
    add(stmt, PLAINTEXTS_STMT(item))
    add(sig, PLAINTEXTS_SIG(item, auth))
  }

  def addPlaintextsSignature(sig: Path, item: Int, auth: Int): Unit = synchronized {
    add(sig, PLAINTEXTS_SIG(item, auth))
  }

  def sync(): MemoryBoardSection = {
    this
  }

  private def add(file: Path, key: String): Unit = {
    val bytes = Files.readAllBytes(file)

    contents += key -> bytes
  }

  private def str(in: Array[Byte]): String = {
    new String(in, StandardCharsets.UTF_8)
  }
}