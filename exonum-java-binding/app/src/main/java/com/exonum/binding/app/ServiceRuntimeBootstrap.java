/*
 * Copyright 2019 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.exonum.binding.app;

import static com.google.common.base.StandardSystemProperty.JAVA_VM_NAME;
import static com.google.common.base.StandardSystemProperty.JAVA_VM_VERSION;
import static com.google.common.base.StandardSystemProperty.OS_ARCH;
import static com.google.common.base.StandardSystemProperty.OS_NAME;
import static com.google.common.base.StandardSystemProperty.OS_VERSION;

import com.exonum.binding.common.hash.HashCode;
import com.exonum.binding.core.runtime.FrameworkModule;
import com.exonum.binding.core.runtime.ServiceRuntimeAdapter;
import com.exonum.binding.core.service.Service;
import com.exonum.binding.core.util.LibraryLoader;
import com.exonum.binding.time.TimeSchema;
import com.exonum.messages.core.runtime.Base.ArtifactId;
import com.google.common.base.StandardSystemProperty;
import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.Stage;
import com.google.protobuf.MessageLite;
import io.vertx.core.Vertx;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pf4j.PluginManager;

/**
 * A bootstrap loader of the service runtime.
 */
public final class ServiceRuntimeBootstrap {

  /**
   * The application stage, configuring Guice behaviour. Can be made configurable if needed.
   */
  private static final Stage APP_STAGE = Stage.PRODUCTION;

  /**
   * Dependency reference classes used to validate that service artifacts don't contain copies of
   * the classes used in Exonum public APIs and loaded by the application classloader.
   *
   * @see <a href="https://exonum.com/doc/version/1.0.0/get-started/java-binding/#using-libraries">Exonum dependencies</a>
   */
  public static final ImmutableMap<String, Class<?>> DEPENDENCY_REFERENCE_CLASSES =
      ImmutableMap.<String, Class<?>>builder()
          .put("exonum-messages", ArtifactId.class)
          .put("exonum-java-binding-core", Service.class)
          .put("exonum-java-binding-common", HashCode.class)
          .put("exonum-time-oracle", TimeSchema.class)
          .put("protobuf-java", MessageLite.class)
          .put("vertx", Vertx.class)
          .put("gson", Gson.class)
          .put("guava", ImmutableMap.class)
          .put("guice", Guice.class)
          .put("pf4j", PluginManager.class)
          .put("log4j", LogManager.class)
          .build();

  private static final Logger logger = LogManager.getLogger(ServiceRuntimeBootstrap.class);

  /**
   * Bootstraps a Java service runtime.
   *
   * @param serviceArtifactsDir the directory in which administrators place and from which
   *     the service runtime loads service artifacts
   * @param serverPort a port for the web server providing transport to Java services
   * @return a new service runtime
   */
  public static ServiceRuntimeAdapter createServiceRuntime(String serviceArtifactsDir,
                                                           int serverPort) {
    try {
      // Log the information about the runtime and environment
      logRuntimeInfo();

      // Load the native libraries early
      LibraryLoader.load();

      // Create the framework injector
      Module frameworkModule = new FrameworkModule(Paths.get(serviceArtifactsDir), serverPort,
          DEPENDENCY_REFERENCE_CLASSES);
      Injector frameworkInjector = Guice.createInjector(APP_STAGE, frameworkModule);

      return frameworkInjector.getInstance(ServiceRuntimeAdapter.class);
    } catch (Throwable t) {
      logger.fatal("Failed to create the Java Service Runtime", t);
      throw t;
    }
  }

  private static void logRuntimeInfo() {
    logExonumInfo();
    logVmInfo();
    logOsInfo();
  }

  private static void logExonumInfo() {
    Properties buildProperties = readBuildProperties();
    String version = buildProperties.getProperty("version");
    String revision = buildProperties.getProperty("revision");
    long timestamp = Long.parseLong(buildProperties.getProperty("timestamp"));
    ZonedDateTime buildTime = ZonedDateTime.ofInstant(Instant.ofEpochMilli(timestamp),
        ZoneOffset.UTC);
    logger.info("Starting Java Service Runtime {} (revision {}, built on {})",
        version, revision, buildTime);
  }

  private static Properties readBuildProperties() {
    Properties buildProperties = new Properties();
    try {
      ClassLoader cl = ServiceRuntimeBootstrap.class.getClassLoader();
      InputStream in = cl.getResourceAsStream("build.properties");
      //noinspection ConstantConditions
      buildProperties.load(in);
    } catch (IOException e) {
      // Log and return the empty properties
      logger.warn("Failed to load the build properties", e);
    }
    return buildProperties;
  }

  private static void logVmInfo() {
    // Log VM info, e.g., OpenJDK 64-Bit Server VM (build 12.0.1+12)
    String name = getSysProperty(JAVA_VM_NAME);
    String version = getSysProperty(JAVA_VM_VERSION);
    logger.info("    VM: {} (build {})", name, version);
  }

  private static void logOsInfo() {
    // Log OS info, e.g. Linux 4.15.0-50-generic amd64
    String name = getSysProperty(OS_NAME);
    String version = getSysProperty(OS_VERSION);
    String arch = getSysProperty(OS_ARCH);
    logger.info("    OS: {} {} {}", name, version, arch);
  }

  private static String getSysProperty(StandardSystemProperty property) {
    return property.value();
  }

  private ServiceRuntimeBootstrap() {}
}
