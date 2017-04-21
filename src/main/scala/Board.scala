package org.nvotes.trustee

import org.eclipse.jgit.api.Git
import org.eclipse.jgit.api.errors.GitAPIException
import org.eclipse.jgit.lib.Ref
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.storage.file.FileRepositoryBuilder
import org.eclipse.jgit.revwalk._
import org.eclipse.jgit.treewalk._
import org.eclipse.jgit.treewalk.filter.PathFilter
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.AnyObjectId
import org.eclipse.jgit.transport._
import org.eclipse.jgit.transport.OpenSshConfig.Host
import com.jcraft.jsch.Session
import org.eclipse.jgit.api.TransportConfigCallback
import org.eclipse.jgit.api.ResetCommand.ResetType
import org.eclipse.jgit.transport.RemoteRefUpdate
import org.eclipse.jgit.transport.PushResult

import java.io.File
import java.io.InputStream
import java.io.IOException
import java.nio.file.Paths
import java.nio.file.Path
import java.nio.file.Files
import java.net.URI
import java.util.UUID
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import scala.collection.mutable.Map

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/** Symbolic constants for protocol files.
 *
 *  Some of these are parameterized by authority and item, and are
 *  therefore methods.
 */
trait Names {
  val CONFIG = "config.json"
  def CONFIG_STMT = s"config.stmt.json"
  def CONFIG_SIG(auth: Int) = s"$auth/config.sig.ucb"

  def PAUSE = "pause"

  def ERROR = "error"
  def ERROR(auth: Int) = s"$auth/error"

  def SHARE(item: Int, auth: Int) = s"$auth/$item/share.ucs.json"
  def SHARE_STMT(item: Int, auth: Int) = s"$auth/$item/share.stmt.json"
  def SHARE_SIG(item: Int, auth: Int) = s"$auth/$item/share.sig.ucb"

  def PUBLIC_KEY(item: Int) = s"1/$item/public_key.ucb"
  def PUBLIC_KEY_STMT(item: Int) = s"1/$item/public_key.stmt.json"
  def PUBLIC_KEY_SIG(item: Int, auth: Int) = s"$auth/$item/public_key.sig"

  def BALLOTS(item: Int) = s"bb/$item/ballots.ucb"
  def BALLOTS_STMT(item: Int) = s"bb/$item/ballot.stmt.json"
  def BALLOTS_SIG(item: Int) = s"bb/$item/ballot.sig"

  // since we are using a local memory storage, this entry will
  // be used as a map key name, not a file name
  // the entry in the map will be a libmix PreShuffleData object
  def PERM_DATA(item: Int, auth: Int) = s"$auth/$item/perm_data"

  def MIX(item: Int, auth: Int) = s"$auth/$item/mix.ucs"
  def MIX_STMT(item: Int, auth: Int) = s"$auth/$item/mix.stmt.json"
  // auth: the auth who produced the mix, auth2: the signing auth
  def MIX_SIG(item: Int, auth: Int, auth2: Int) = s"$auth2/$item/mix.$auth.sig.ucb"

  def DECRYPTION(item: Int, auth: Int) = s"$auth/$item/decryption.json"
  def DECRYPTION_STMT(item: Int, auth: Int) = s"$auth/$item/decryption.stmt.json"
  def DECRYPTION_SIG(item: Int, auth: Int) = s"$auth/$item/decryption.sig.ucb"

  def PLAINTEXTS(item: Int) = s"1/$item/plaintexts.json"
  def PLAINTEXTS_STMT(item: Int) = s"1/$item/plaintext.stmt.json"
  def PLAINTEXTS_SIG(item: Int, auth: Int) = s"$auth/$item/plaintext.sig.ucb"
}


/** Factory methods for Boards
 *
 */
object Board {
  /** Returns a Board whose datastore is the provided Path */
  def get(dataStorePath: Path) = {
    new Board(dataStorePath)
  }
}

/** A Bulletin Board
 *
 *  A Board is composed of BoardSections. A Board has an associated
 *  datastore path.
 *
 *  The constructor throws exception if
 *  - The datastore path does not exist
 *  - The datastore is not a directory
 *
 *  A datastore is simply a directory, whose subdirectories contain
 *  repositories targeted by BoardSections.
 */
class Board (val dataStorePath: Path) {
  val logger = LoggerFactory.getLogger(classOf[Board])

  if(!Files.exists(dataStorePath)) {
    throw new IllegalArgumentException(s"datastore '$dataStorePath' does not exist")
  }
  if(!Files.isDirectory(dataStorePath)) {
    throw new IllegalArgumentException(s"datastore '$dataStorePath' is not a directory")
  }

  /** Returns a newly created BoardSection whose target is a repository at a uniquely
    generated path */
  def createSection(): BoardSection = {
    val id = UUID.randomUUID().toString
    val repoPath = dataStorePath.resolve(id)
    BoardSection.create(repoPath)
  }

  /** Returns a new BoardSection whose target is a repository at the supplied Path
   *
   *  Throws exception if
   *  - the target does not exist
   *  - the target is not a directory
   */
  def openSection(path: Path) = {
    val repoPath = dataStorePath.resolve(path)
    if(!Files.exists(repoPath)) {
      throw new IllegalArgumentException(s"datastore '$dataStorePath' does not exist")
    }
    if(!Files.isDirectory(repoPath)) {
      throw new IllegalArgumentException(s"datastore '$dataStorePath' is not a directory")
    }

    BoardSection(GitRepo(repoPath))
  }

  /** Returns a new BoardSection whose target is a newly cloned repository. */
  def cloneSection(url: URI, path: Path): BoardSection = {
    BoardSection.clone(url, dataStorePath.resolve(path))
  }

  /** Returns a new Board Section that points to a repository that is cloned
    if it does not yet exist, otherwise is synced */
  def cloneOrSyncSection(url: URI, path: Path): BoardSection = {
    BoardSection.cloneOrSync(url, dataStorePath.resolve(path))
  }

  /** Returns the list of BoardSections contained by the current Board
   *
   *  A BoardSection is contained by the Board when it's target repository
   *  exists at Path which is a descendant (subdirectory) of the Board's datastore.
   *
   */
  def readBoardSections: Set[BoardSection] = {
    import scala.collection.JavaConverters._

    val stream = Files.newDirectoryStream(dataStorePath)
    try {
      stream.asScala
      .filter(Files.isDirectory(_))
      .map(path => BoardSection(GitRepo(path)))
      .toSet
    }
    finally {
      stream.close
    }
  }
}

/** A section of the Board. Typically corresponds to an election.
 *
 *  This implementation has one git repository as its backend. Operations are
 *  named according to the protocol, and are mapped to git operations
 *  internally.
 *
 *  Methods that may alter or read from the backend must be synchronized
 *  for thread safety, as this is not provided by jgit. If this is
 *  done correctly the protocol may be executed with parallelism on a
 *  per-item basis.
 *
 *  Posting to the board section follows the same pattern. First the
 *  repository is synced, then the files are added to the working copy,
 *  and finally the changes are pushed. Syncing before posting minimizes
 *  the chances that the push is rejected (NON-FAST-FORWARD) for being
 *  out of date.
 *
 *  Methods that retrieve files always return Options as they may not exist.
 *
 */
case class BoardSection (val gitRepo: GitRepo) extends Names {
  val logger = LoggerFactory.getLogger(classOf[BoardSection])

  val preShuffleData = Map[String, PreShuffleData]()

  /** Returns the name of the BoardSection, which is its target Path */
  def name: String = gitRepo.repoPath.getName(gitRepo.repoPath.getNameCount - 1).toString

  /** Returns the set of all entries in this section
   *
   *  The preShuffleData memory storage area is included
   *  to allow transparent access to its data as if it were
   *  a regular file in the repository
   */
  def getFileSet: Set[String] = synchronized {
    logger.info(s"Permutation data map size: ${preShuffleData.size}")
    gitRepo.getFileSet() ++ preShuffleData.keySet
  }

  /** Syncs the repository, adds the error, and sends
   *
   *  If an error already existed it is removed from the working copy
   *  first (previous errros will exist in the git history)
   */
  def addError(error: Path, position: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(error, ERROR(position))
    gitRepo.send("error", ERROR(position))
  }

  /** Returns the configuration if it exists as an Option[String] */
  def getConfig: Option[String] = getFileStream(CONFIG).map(IO.asString(_))

  /** Returns the configuration if it exists as an Option[InputStream] */
  def getConfigStream: Option[InputStream] = getFileStream(CONFIG)

  /** Returns the configuration statement if it exists */
  def getConfigStatement: Option[String] = getFileStream(CONFIG_STMT).map(IO.asString(_))

  /** Returns the configuration statement signature if it exists */
  def getConfigSignature(auth: Int): Option[Array[Byte]] = {
    getFileStream(CONFIG_SIG(auth)).map(IO.asBytes(_))
  }

  /** Syncs the repository, adds the configuration, and sends */
  def addConfig(config: Path): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(config, CONFIG)
    gitRepo.send("added config", CONFIG)
  }

  /** Syncs the repository, adds the configuration signature, and sends */
  def addConfigSig(sig: Path, position: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(sig, CONFIG_SIG(position))
    gitRepo.send("added config signature", CONFIG_SIG(position))
  }

  /** Syncs the repository, adds a share triple (Share, Statement, Signature), and sends */
  def addShare(share: Path, stmt: Path, sig: Path, item: Int, position: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(share, SHARE(item, position))
    gitRepo.addToWorkingCopy(stmt, SHARE_STMT(item, position))
    gitRepo.addToWorkingCopy(sig, SHARE_SIG(item, position))
    gitRepo.send("added share", SHARE(item, position), SHARE_STMT(item, position), SHARE_SIG(item, position))
  }

  /** Returns a share if it exists */
  def getShare(item: Int, auth: Int): Option[String] = {
    getFileStream(SHARE(item, auth)).map(IO.asString(_))
  }

  /** Returns a share statement if it exists */
  def getShareStatement(item: Int, auth: Int): Option[String] = {
    getFileStream(SHARE_STMT(item, auth)).map(IO.asString(_))
  }

  /** Returns a share signature if it exists */
  def getShareSignature(item: Int, auth: Int): Option[Array[Byte]] = {
    getFileStream(SHARE_SIG(item, auth)).map(IO.asBytes(_))
  }

  /** Syncs the repository, adds a share triple (Share, Statement, Signature), and sends */
  def addPublicKey(publicKey: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(publicKey, PUBLIC_KEY(item))
    gitRepo.addToWorkingCopy(stmt, PUBLIC_KEY_STMT(item))
    gitRepo.addToWorkingCopy(sig, PUBLIC_KEY_SIG(item, auth))
    gitRepo.send("added public key", PUBLIC_KEY(item), PUBLIC_KEY_STMT(item), PUBLIC_KEY_SIG(item, auth))
  }

  /** Syncs the repository, adds a public key signature, and sends */
  def addPublicKeySignature(sig: Path, item: Int, auth: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(sig, PUBLIC_KEY_SIG(item, auth))
    gitRepo.send("added public key signature", PUBLIC_KEY_SIG(item, auth))
  }

  /** Returns the public key if it exists */
  def getPublicKey(item: Int): Option[String] = {
    getFileStream(PUBLIC_KEY(item)).map(IO.asString(_))
  }

  /** Returns the public key statement if it exists */
  def getPublicKeyStatement(item: Int): Option[String] = {
    getFileStream(PUBLIC_KEY_STMT(item)).map(IO.asString(_))
  }

  /** Returns the public key signature if it exists */
  def getPublicKeySignature(item: Int, auth: Int): Option[Array[Byte]] = {
    getFileStream(PUBLIC_KEY_SIG(item, auth)).map(IO.asBytes(_))
  }

  /** Returns the ballots if they exist */
  def getBallots(item: Int): Option[String] =  {
    getFileStream(BALLOTS(item)).map(IO.asString(_))
  }

  /** Returns the ballots statement if it exists */
  def getBallotsStatement(item: Int): Option[String] =  {
    getFileStream(BALLOTS_STMT(item)).map(IO.asString(_))
  }

  /** Returns the ballots signature if it exists */
  def getBallotsSignature(item: Int): Option[Array[Byte]] =  {
    getFileStream(BALLOTS_SIG(item)).map(IO.asBytes(_))
  }

  /** Syncs the repository, adds a share triple (Share, Statement, Signature), and sends */
  def addBallots(ballots: Path, stmt: Path, sig: Path, item: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(ballots, BALLOTS(item))
    gitRepo.addToWorkingCopy(stmt, BALLOTS_STMT(item))
    gitRepo.addToWorkingCopy(sig, BALLOTS_SIG(item))
    gitRepo.send("added ballots", BALLOTS(item), BALLOTS_STMT(item), BALLOTS_SIG(item))
  }

  /** Returns private permutation data if it exists */
  def getPreShuffleDataLocal(item: Int, auth: Int): Option[PreShuffleData] = synchronized {
    preShuffleData.get(PERM_DATA(item, auth))
  }

  /** Adds private permutation data */
  def addPreShuffleDataLocal(data: PreShuffleData, item: Int, auth: Int) = synchronized {
    preShuffleData += PERM_DATA(item, auth) -> data
  }

  /** Remove private permutation data */
  def rmPreShuffleDataLocal(item: Int, auth: Int) = synchronized {
    preShuffleData -= PERM_DATA(item, auth)
  }

  /** Returns a mix if it exists */
  def getMix(item: Int, auth: Int): Option[String] =  {
    getFileStream(MIX(item, auth)).map(IO.asString(_))
  }

  /** Returns a mix statement if it exists */
  def getMixStatement(item: Int, auth: Int): Option[String] = {
    getFileStream(MIX_STMT(item, auth)).map(IO.asString(_))
  }

  /** Returns a mix signature if it exists */
  def getMixSignature(item: Int, auth: Int, auth2: Int): Option[Array[Byte]] = {
    getFileStream(MIX_SIG(item, auth, auth2)).map(IO.asBytes(_))
  }

  /** Syncs the repository, adds a share triple (Share, Statement, Signature), and sends */
  def addMix(mix: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(mix, MIX(item, auth))
    gitRepo.addToWorkingCopy(stmt, MIX_STMT(item, auth))
    gitRepo.addToWorkingCopy(sig, MIX_SIG(item, auth, auth))
    gitRepo.send("added mix", MIX(item, auth), MIX_STMT(item, auth), MIX_SIG(item, auth, auth))
  }

  /** Syncs the repository, adds a mix signature, and sends */
  def addMixSignature(sig: Path, item: Int, authMixer: Int, authSigner: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(sig, MIX_SIG(item, authMixer, authSigner))
    gitRepo.send("added mix signature", MIX_SIG(item, authMixer, authSigner))
  }

  /** Returns a decryption if it exists */
  def getDecryption(item: Int, auth: Int): Option[String] = {
    getFileStream(DECRYPTION(item, auth)).map(IO.asString(_))
  }

  /** Returns a decryption statement if it exists */
  def getDecryptionStatement(item: Int, auth: Int): Option[String] = {
    getFileStream(DECRYPTION_STMT(item, auth)).map(IO.asString(_))
  }

  /** Returns a decryption signature if it exists */
  def getDecryptionSignature(item: Int, auth: Int): Option[Array[Byte]] = {
    getFileStream(DECRYPTION_SIG(item, auth)).map(IO.asBytes(_))
  }

  /** Syncs the repository, adds a share triple (Share, Statement, Signature), and sends */
  def addDecryption(decryption: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(decryption, DECRYPTION(item, auth))
    gitRepo.addToWorkingCopy(stmt, DECRYPTION_STMT(item, auth))
    gitRepo.addToWorkingCopy(sig, DECRYPTION_SIG(item, auth))
    gitRepo.send("added decryption", DECRYPTION(item, auth), DECRYPTION_STMT(item, auth), DECRYPTION_SIG(item, auth))
  }

  /** Returns the plaintexts if they exist */
  def getPlaintexts(item: Int): Option[String] = {
    getFileStream(PLAINTEXTS(item)).map(IO.asString(_))
  }

  /** Returns the plaintexts statement if it exists */
  def getPlaintextsStatement(item: Int): Option[String] = {
    getFileStream(PLAINTEXTS_STMT(item)).map(IO.asString(_))
  }

  /** Returns the plaintexts signature if it exists */
  def getPlaintextsSignature(item: Int, auth: Int): Option[Array[Byte]] = {
    getFileStream(PLAINTEXTS_SIG(item, auth)).map(IO.asBytes(_))
  }

  /** Syncs the repository, adds a share triple (Share, Statement, Signature), and sends */
  def addPlaintexts(plaintexts: Path, stmt: Path, sig: Path, item: Int, auth: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(plaintexts, PLAINTEXTS(item))
    gitRepo.addToWorkingCopy(stmt, PLAINTEXTS_STMT(item))
    gitRepo.addToWorkingCopy(sig, PLAINTEXTS_SIG(item, auth))
    gitRepo.send("added plaintexts", PLAINTEXTS(item), PLAINTEXTS_STMT(item), PLAINTEXTS_SIG(item, auth))
  }

  /** Syncs the repository, adds a plaintexts signature, and sends */
  def addPlaintextsSignature(sig: Path, item: Int, auth: Int): Unit = synchronized {
    gitRepo.sync()
    gitRepo.addToWorkingCopy(sig, PLAINTEXTS_SIG(item, auth))
    gitRepo.send("added plaintexts signature", PLAINTEXTS_SIG(item, auth))
  }

  /** Syncs the repository, see the GitRepo implementation for details */
  def sync(): BoardSection = {
    gitRepo.sync()
    this
  }

  /** Sends (posts) to the repository, see the GitRepo implementation for details */
  def send(message: String): Unit = {
    gitRepo.send(message)
  }

  /** Returns an inputstream for a file if it exists. Caller _must_ close the stream */
  // FIXME provide details as to the JGIT filter implementation to select files
  private def getFileStream(file: String): Option[InputStream] = synchronized {
    gitRepo.getFileInputStream(file)
  }
}

/** Provides methods to create Board Sections when their data does not exist locally
 *
 *  If a Board Section has no target diretory, it can be created by
 *  - creating a new repository
 *  - cloning a repository
 *
 */
object BoardSection {

  /** Returns a new Board Section that points to a newly created repository */
  def create(repoPath: Path): BoardSection = {
    val gitRepo = GitRepo.create(repoPath)
    BoardSection(gitRepo)
  }

  /** Returns a new Board Section that points to a newly cloned repository */
  def clone(urlBase: URI, target: Path): BoardSection = {
    val url = urlBase.resolve(target.getName(target.getNameCount - 1).toString)
    val gitRepo = GitRepo.clone(url, target)
    BoardSection(gitRepo)
  }

  /** Returns a new Board Section that points to a repository that is cloned
    if it does not yet exist, otherwise is synced */
  def cloneOrSync(urlBase: URI, target: Path): BoardSection = {
    val url = urlBase.resolve(target.getName(target.getNameCount - 1).toString)
    val gitRepo = GitRepo.cloneOrSync(url, target)
    BoardSection(gitRepo)
  }
}

/** A git repository accessed with the jgit api
 *
 *  Provides (only) the functionality required by Board and BoardSection
 *
 *  The constructor throws exception if
 *  - The target path does not exist
 *  - The target path does not point to a directory
 */
case class GitRepo(val repoPath: Path) {
  val logger = LoggerFactory.getLogger(classOf[GitRepo])
  val noCompression = sys.props.get("nmix.git.disable-compression").getOrElse("false").toBoolean
  logger.info(s"Repo '$repoPath' compression: ${!noCompression}")

  if(!Files.exists(repoPath)) {
    throw new IllegalArgumentException(s"repoPath '$repoPath' does not exist")
  }
  if(!Files.isDirectory(repoPath)) {
    throw new IllegalArgumentException(s"repoPath '$repoPath' is not a directory")
  }

  /** Returns the file input stream for matching file, if it exists
   *
   *  The caller is responsible for
   *  - Checking if the stream exists (Option)
   *  - Closing the input stream (if it exists)
   */
  def getFileInputStream(filter: String): Option[InputStream] = {
    val f = (repository: Repository, treeWalk: Option[TreeWalk]) => {
      treeWalk.flatMap { tw =>
        if (tw.next()) {
          val objectId = tw.getObjectId(0)
          val loader = repository.open(objectId)
          Some(loader.openStream())
        }
        else {
          None
        }
      }
    }
    useTreeWalk(filter, f)
  }

  /** Returns the set of files in repository matching provided filter
   *
   *  The set contains Strings like 'path/to/file'
   */
  def getFileSet(filter: String = ""): Set[String] = {
    val f = (repository: Repository, treeWalk: Option[TreeWalk]) => {
      val ret = new scala.collection.mutable.ArrayBuffer[String]()
      treeWalk.foreach { tw =>
        while(tw.next()) {
          ret += tw.getPathString
        }
      }
      ret.toSet
    }
    useTreeWalk(filter, f)
  }


  /** Adds a file to working copy (not the repository), if not present in repository
   *
   *  This version receives the path as a String
   */
  def addToWorkingCopy(sourceFile: Path, target: String): Unit = {
    addToWorkingCopy(sourceFile, Paths.get(target))
  }

  /** Adds a file to the working copy (not the repository), if not present in repository
   *
   *  The file will not be added if it already exists in the repository. Any
   *  missing directories are created. If the file exists in the working copy
   *  it is deleted.
   *
   *  Throws exception if
   *  - the source file does not exist or is not a regular file
   *  - the target path is absolute or travels up the hierarchy
   */
  def addToWorkingCopy(sourceFile: Path, target: Path): Unit = {
    val targetFile = repoPath.resolve(target)
    if(!Files.exists(sourceFile)) {
      throw new IllegalArgumentException(s"sourceFile '$sourceFile' does not exist")
    }
    if(!Files.isRegularFile(sourceFile)) {
      throw new IllegalArgumentException(s"sourceFile '$sourceFile' is invalid")
    }
    if(targetFile.isAbsolute()) {
      throw new IllegalArgumentException(s"targetPath '$targetFile' is invalid")
    }
    // no up-directory nonsense
    if(!targetFile.startsWith(repoPath)) {
      throw new IllegalArgumentException(s"file name '$targetFile' is invalid")
    }

    // check if file already in repository
    val present = getFileSet(target.toString)
    if(!present.contains(target.toString)) {
      // remove the file first from working copy if it exists
      Files.deleteIfExists(targetFile)

      // create necessary directories if they are not present
      Files.createDirectories(targetFile.getParent)

      // FIXME use atomic move when not on vm
      // copy the file
      // Files.copy(sourceFile, targetFile)
      // Files.move(sourceFile, targetFile, ATOMIC_MOVE)
      Files.move(sourceFile, targetFile)
    }
    else {
      logger.warn(s"file '$target' already exists, skipping")
    }
  }

  /** Adds, commits and pushes any changes in the working copy
   *
   * If the push fails due to non-fast-forward, pulls and retries up to 7 times.
   * Atomic push is requested and needs git 2.4+ on the server.
   *
   */
  def send(message: String, files: String*) = {
    val t0 = System.nanoTime()

    val repository = buildRepo
    val git = new Git(repository)

    try {
      var start = System.nanoTime()
      val addCommand = git.add()
      files.foreach(addCommand.addFilepattern(_))
      addCommand.call()
      var end = System.nanoTime()
      logger.debug("Add time: " + ((end - start) / 1000000000.0) + " s")


      val status = git.status().call()
      val added = status.getAdded()
      val changed = status.getChanged()

      if( (added.size > 0) || (changed.size > 0) ) {

        logger.info(s"Committing ${added.size} additions and ${changed.size} modifications")

        start = System.nanoTime()
        val commit = git.commit()
        files.foreach(commit.setOnly(_))
        commit.setMessage(message)
        commit.call()
        end = System.nanoTime()
        logger.debug("Commit time: " + ((end - start) / 1000000000.0) + " s")

        val attempt = () => {
          start = System.nanoTime()
          val pushCommand = git.push()
          pushCommand.setTransportConfigCallback(GitRepo.sshTransportCallback)
          // requires git 2.4+ on server
          pushCommand.setAtomic(true)
          val results = pushCommand.call()
          end = System.nanoTime()
          logger.debug("Push time: " + ((end - start) / 1000000000.0) + " s")

          val status = getPushStatus(results)
          logger.info(s"push status: $status")

          // http://download.eclipse.org/jgit/site/4.6.1.201703071140-r/apidocs/index.html
          if(status != RemoteRefUpdate.Status.OK) {
            logger.warn(s"Push status was not OK: $status")
            if(status == RemoteRefUpdate.Status.REJECTED_NONFASTFORWARD) {
              logger.warn(s"Attempting to recover non fast forward")
              start = System.nanoTime()
              val pullCommand = git.pull()
              pullCommand.setTransportConfigCallback(GitRepo.sshTransportCallback)
              val result = pullCommand.call()
              end = System.nanoTime()
              logger.debug("Pull (recover) time: " + ((end - start) / 1000000000.0) + " s")
              logger.info(s"pull command, fetch: ${result.getFetchResult.toString}, merge ${result.getMergeResult.toString}")
            }
          }

          status
        }

        val attempts = List.fill(8)(attempt)
        attempts.takeWhile(_() != RemoteRefUpdate.Status.OK)
      }
      else {
        logger.warn("no changes to commit")
      }
    }
    finally {
      repository.close()
      git.close()
    }

    val t1 = System.nanoTime()
    logger.info("Send time: " + ((t1 - t0) / 1000000000.0) + " s")
  }

  /** Sync's the repository and working copy with remote
   *
   *  1) Updates the repository from remote (fetch)
   *  2) Discards all unstaged changes and unpushed commits (reset)
   *  3) Removes all unknown files (clean)
   */
  def sync(): GitRepo = {
    val t0 = System.nanoTime()

    val repository = buildRepo
    val git = new Git(repository)

    try {
      var start = System.nanoTime()

      val fetchCommand = git.fetch().setCheckFetchedObjects(true)
      fetchCommand.setTransportConfigCallback(GitRepo.sshTransportCallback)
      fetchCommand.setRemote("origin")
      val result = fetchCommand.call()

      var end = System.nanoTime()
      logger.debug("Fetch time: " + ((end - start) / 1000000000.0) + " s")

      start = System.nanoTime()
      git.reset().setMode(ResetType.HARD).setRef("origin/master").call()
      end = System.nanoTime()
      logger.debug("Reset time: " + ((end - start) / 1000000000.0) + " s")

      start = System.nanoTime()
      git.clean().setCleanDirectories(true).call()
      end = System.nanoTime()
      logger.debug("Clean time: " + ((end - start) / 1000000000.0) + " s")
    }
    finally {
      repository.close()
      git.close()
    }
    val t1 = System.nanoTime()
    logger.info("Sync time: " + ((t1 - t0) / 1000000000.0) + " s")

    this
  }

  /** Convenience method to operate against a Treewak with a provided function
   *
   *  The function method is provided a Repository and a Treewalk.
   *  Resources are automatically closed.
   */
  private def useTreeWalk[T](filter: String = "", f: (Repository, Option[TreeWalk]) => T): T = {

    val repository = buildRepo
    val git = new Git(repository)

    try {
      val head = repository.resolve(Constants.HEAD)
      if(head != null) {
        val revWalk = new RevWalk(repository)
        val commit = revWalk.parseCommit(head)
        val tree = commit.getTree()

        val treeWalk = new TreeWalk(repository)
        treeWalk.addTree(tree)
        treeWalk.setRecursive(true)

        if(filter.length > 0) {
          treeWalk.setFilter(PathFilter.create(filter))
        }

        val ret = f(repository, Some(treeWalk))

        treeWalk.close()
        revWalk.dispose()

        ret
      }
      else {
        f(repository, None)
      }
    }
    finally {
      repository.close()
      git.close()
    }
  }

  /** Convenience method to build jgit api repository
   *
   *  TODO: exceptions
   */
  private def buildRepo: Repository = {
    val builder = new FileRepositoryBuilder()
    val repo = builder.setGitDir(repoPath.resolve(".git").toFile)
      .readEnvironment()
      .setMustExist(true)
      .build()

    if(noCompression) {
      repo.getConfig().setString("pack", null, "window", "0")
      repo.getConfig().setString("core", null, "bigFileThreshold", "1")
      repo.getConfig().setString("pack", null, "compression", "0")
      repo.getConfig().setString("core", null, "compression", "0")
      repo.getConfig().setString("core", null, "looseCompression", "0")
    }

    repo
  }

  /** Convenience method to return the push status
   *
   *  Assumes there is only one result and remote update, returns
   *  the first status.
   */
  private def getPushStatus(results: java.lang.Iterable[PushResult]): RemoteRefUpdate.Status = {
    import scala.collection.JavaConverters._

    val status = results.asScala.head.getRemoteUpdates.asScala.head
    status.getStatus
  }
}

/** Companion object used to create and clone remote repositories
 *
 *  Includes jgit machinery for remote connections via ssh
 */
object GitRepo {
  val logger = LoggerFactory.getLogger(GitRepo.getClass)

  /** Jgit machinery for ssh transports */
  val sshSessionFactory = new JschConfigSessionFactory() {
    override protected def configure(host: Host, session: Session) = {
      // http://stackoverflow.com/questions/13396534/unknownhostkey-exception-in-accessing-github-securely
      session.setConfig("StrictHostKeyChecking", "no")
    }
  }
  val sshTransportCallback = new TransportConfigCallback() {
    override def configure(transport: Transport) = {
      val sshTransport = transport.asInstanceOf[SshTransport]
      sshTransport.setSshSessionFactory(sshSessionFactory)
    }
  }

  /** Creates a repository
   *
   *  FIXME: this method is unused, and should create bare repositories
   *  if necessary for the boostrap process (eg electionmanager)
   */
  def create(repoPath: Path) = {
    if(Files.exists(repoPath)) {
      throw new IllegalArgumentException(s"repoPath '$repoPath' already exists")
    }
    val repoFile = Files.createDirectory(repoPath).toFile
    val git = Git.init().setDirectory(repoFile).call()
    git.close()
    GitRepo(repoPath)
  }

  /** Clone repository
   *
   *  Throws exception if the target directory already exists
   */
  def clone(url: URI, target: Path) = {
    if(Files.exists(target)) {
      throw new IllegalArgumentException(s"target directory '$target' already exists")
    }

    val cloneCommand = Git.cloneRepository()
    cloneCommand.setURI(url.toString)
    cloneCommand.setTransportConfigCallback(sshTransportCallback)

    cloneCommand.setDirectory(target.toFile)
    val git = cloneCommand.call()
    git.close()

    GitRepo(target)
  }

  /** Clones the repository if it does not exist. If it does, syncs it
   *
   */
  def cloneOrSync(url: URI, target: Path): GitRepo = {
    if(!Files.exists(target)) {
      val cloneCommand = Git.cloneRepository()
      cloneCommand.setURI(url.toString)
      cloneCommand.setTransportConfigCallback(sshTransportCallback)

      cloneCommand.setDirectory(target.toFile)
      val git = cloneCommand.call()
      git.close()
      GitRepo(target)
    } else {
      GitRepo(target).sync()
    }
  }
}