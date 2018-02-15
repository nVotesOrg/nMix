name := "nMix"
version := "0.2-SNAPSHOT"

scalaVersion := "2.12.4"

resolvers ++= Seq(
  Resolver.sonatypeRepo("releases"),
  Resolver.sonatypeRepo("snapshots"),
  MavenRepository("jgit-repository", "http://download.eclipse.org/jgit/maven")
)

libraryDependencies ++= Seq(
  "org.eclipse.jgit" % "org.eclipse.jgit" % "4.10.0.201712302008-r",
  "com.github.pureconfig" %% "pureconfig" % "0.9.0",
  "org.slf4j" % "slf4j-simple" % "1.7.25"
)

val scalatestVersion = "3.0.4"
libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest",
  "org.scalactic" %% "scalactic"
).map(_ % scalatestVersion % "test")

val circeVersion = "0.9.1"
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

scalacOptions ++= Seq("-feature", "-language:existentials", "-deprecation", "-opt:l:inline")
javacOptions ++= Seq("-deprecation")
