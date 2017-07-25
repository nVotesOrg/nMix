package org.nvotes.mix

import java.nio.file.Paths
import java.nio.file.Files

import org.scalatest.FlatSpec
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Tests the local repo functionality. Remoting is not tested
 *
 */
class BulletinBoardSpec extends FlatSpec {

  "Board creation" should "fail with bad arguments" in {
    assertThrows[IllegalArgumentException] {
      val board = new Board(Paths.get("does not exist"))
    }
    assertThrows[IllegalArgumentException] {
      val board = new Board(Files.createTempFile("nmix", ".tmp"))
    }
  }

  "Board creation" should "work with good arguments" in {
    val tmp = Files.createTempDirectory("nmix")
    val board = new Board(tmp)
    val section = board.createSection()
    assert(section.getFileSet.size == 0)
  }

  "Uploading with invalid arguments" should "not work" in {
    val tmp = Files.createTempDirectory("nmix")
    val board = new Board(tmp)
    val section = board.createSection()
    val file = Files.createTempFile("test", ".tmp")
    val directory = Files.createTempDirectory("test")
    assertThrows[IllegalArgumentException] {
      section.gitRepo.addToWorkingCopy(Paths.get("does not exist"), "path")
    }
    assertThrows[IllegalArgumentException] {
      section.gitRepo.addToWorkingCopy(directory, "path")
    }
    assertThrows[IllegalArgumentException] {
      section.gitRepo.addToWorkingCopy(file, "/absolute_path")
    }
    assertThrows[IllegalArgumentException] {
      section.gitRepo.addToWorkingCopy(file, "../upwards")
    }
    assertThrows[IllegalArgumentException] {
      section.gitRepo.addToWorkingCopy(file, "../../upwards")
    }
  }

  "Uploading with valid arguments" should "work" in {
    val tmp = Files.createTempDirectory("nmix")
    val board = new Board(tmp)
    val section = board.createSection()
    val file = Files.createTempFile("test", ".tmp")
    section.gitRepo.addToWorkingCopy(file, "path")
    assert(Files.exists(section.gitRepo.repoPath.resolve("path")))
    val file2 = Files.createTempFile("test", ".tmp")
    section.gitRepo.addToWorkingCopy(file2, "a/b/c")
    assert(Files.exists(section.gitRepo.repoPath.resolve("a/b/c")))
  }
}