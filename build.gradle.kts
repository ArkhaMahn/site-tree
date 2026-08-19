import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    java
    id("org.zaproxy.add-on") version "0.13.1"
}

group = "org.zaproxy.addon"
version = "1.1.0"
description =
    "Network-layer Burp-style link extraction: runs inline on every response ZAP receives and, for " +
        "in-scope sources, adds URLs discovered in HTML/JS/CSS/JSON/XML bodies to the Sites tree as " +
        "unrequested (TYPE_ZAP_USER) entries, without sending any requests to them."

repositories {
    mavenCentral()
}

java {
    // ZAP 2.17.0 requires Java 17 or above.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testImplementation("org.zaproxy:zap:2.17.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

zapAddOn {
    addOnName.set("Site tree")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.17.0")

    manifest {
        author.set("Arkhamahn")
        url.set("https://github.com/ArkhaMahn/site-tree")
        bundle {
            baseName.set("org.zaproxy.addon.linkextractor.resources.Messages")
            prefix.set("linkextractor")
        }
    }
}

tasks.withType<JavaCompile> { options.compilerArgs.add("-Xlint:deprecation") }

tasks.withType<Test> {
    useJUnitPlatform()
}