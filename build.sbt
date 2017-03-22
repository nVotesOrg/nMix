name := "nMix"
version := "0.2-SNAPSHOT"

scalaVersion := "2.12.1"

resolvers ++= Seq(
  Resolver.sonatypeRepo("releases"),
  Resolver.sonatypeRepo("snapshots")
)
resolvers += "jgit-repository" at "http://download.eclipse.org/jgit/maven"

libraryDependencies ++= Seq(
  "org.eclipse.jgit" % "org.eclipse.jgit" % "4.5.0.201609210915-r",
  "com.github.melrief" %% "pureconfig" % "0.6.0",
  "org.slf4j" % "slf4j-simple" % "1.6.4",
  // "com.squareup.jnagmp" % "jnagmp" % "2.0.0",
  "org.scalatest" %% "scalatest" % "3.0.1" % "test",
  "org.scalactic" %% "scalactic" % "3.0.1" % "test"
)

val circeVersion = "0.7.0"
libraryDependencies ++= Seq(
  "io.circe" %% "circe-core",
  "io.circe" %% "circe-generic",
  "io.circe" %% "circe-parser"
).map(_ % circeVersion)

test in assembly := {}
assemblyOption in assembly := (assemblyOption in assembly).value.copy(includeScala = false, includeDependency = false)

cancelable in Global := true
fork in run := false
fork in Test := false