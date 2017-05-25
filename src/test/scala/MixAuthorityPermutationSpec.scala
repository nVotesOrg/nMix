package org.nvotes.mix

import java.nio.file.Paths

import org.scalatest.FlatSpec
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Tests the authority permutation mix position
 *
 */
class MixAuthorityPermutationSpec extends FlatSpec {

  val files = Set("config.json", "config_1.stmt", "config_1.sig", "1/error")

  "permutation and inverse should" should "be consistent" in {
    var auth = 1
    var position = Protocol.getMixPosition(auth, 1, 2)
    var auth_match = Protocol.getTrusteeForMixPosition(position, 1, 2)
    assert(auth == auth_match)

    auth = 1
    position = Protocol.getMixPosition(auth, 2, 2)
    auth_match = Protocol.getTrusteeForMixPosition(position, 2, 2)
    assert(auth == auth_match)

    auth = 1
    position = Protocol.getMixPosition(auth, 3, 2)
    auth_match = Protocol.getTrusteeForMixPosition(position, 3, 2)
    assert(auth == auth_match)

    auth = 2
    position = Protocol.getMixPosition(auth, 1, 2)
    auth_match = Protocol.getTrusteeForMixPosition(position, 1, 2)
    assert(auth == auth_match)

    auth = 2
    position = Protocol.getMixPosition(auth, 2, 2)
    auth_match = Protocol.getTrusteeForMixPosition(position, 2, 2)
    assert(auth == auth_match)

    auth = 2
    position = Protocol.getMixPosition(auth, 3, 2)
    auth_match = Protocol.getTrusteeForMixPosition(position, 3, 2)
    assert(auth == auth_match)

    auth = 1
    position = Protocol.getMixPosition(auth, 1, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 1, 3)
    assert(auth == auth_match)

    auth = 1
    position = Protocol.getMixPosition(auth, 2, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 2, 3)
    assert(auth == auth_match)

    auth = 1
    position = Protocol.getMixPosition(auth, 3, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 3, 3)
    assert(auth == auth_match)

    auth = 2
    position = Protocol.getMixPosition(auth, 1, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 1, 3)
    assert(auth == auth_match)

    auth = 2
    position = Protocol.getMixPosition(auth, 2, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 2, 3)
    assert(auth == auth_match)

    auth = 2
    position = Protocol.getMixPosition(auth, 3, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 3, 3)
    assert(auth == auth_match)

    auth = 3
    position = Protocol.getMixPosition(auth, 1, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 1, 3)
    assert(auth == auth_match)

    auth = 3
    position = Protocol.getMixPosition(auth, 2, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 2, 3)
    assert(auth == auth_match)

    auth = 3
    position = Protocol.getMixPosition(auth, 3, 3)
    auth_match = Protocol.getTrusteeForMixPosition(position, 3, 3)
    assert(auth == auth_match)
  }
}