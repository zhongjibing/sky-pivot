package com.icezhg.sky.pivot.opaque;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

@DisplayName("ServerSideCryptoBan Tests")
class ServerSideCryptoBanTest {

    private static final Path BACKEND_SRC = Paths.get(System.getProperty("serverSideCryptoBan.root",
            "src/main/java")).toAbsolutePath();

    private static final List<Path> SERVER_PACKAGES = List.of(
            Path.of("com/icezhg/sky/pivot/controller"),
            Path.of("com/icezhg/sky/pivot/config"),
            Path.of("com/icezhg/sky/pivot/security"),
            Path.of("com/icezhg/sky/pivot/scheduler"),
            Path.of("com/icezhg/sky/pivot/opaque/config"),
            Path.of("com/icezhg/sky/pivot/opaque/service"),
            Path.of("com/icezhg/sky/pivot/opaque/store")
    );

    @Test
    @DisplayName("AC-5: Server-side code must not contain user key derivation or data decryption logic")
    void shouldNotContainBannedCryptoOperations() throws IOException {
        StringBuilder violations = new StringBuilder();

        for (Path pkg : SERVER_PACKAGES) {
            Path dir = BACKEND_SRC.resolve(pkg);
            if (!Files.exists(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                files.filter(Files::isRegularFile)
                        .filter(f -> f.toString().endsWith(".java"))
                        .filter(f -> !f.getFileName().toString().contains("ServerSideCryptoBan"))
                        .filter(f -> !f.getFileName().toString().equals("SkyPivotOpaqueConfig.java"))
                        .filter(f -> !f.getFileName().toString().equals("OpaqueConstants.java"))
                        .forEach(file -> {
                            try {
                                String content = Files.readString(file, StandardCharsets.UTF_8);
                                for (String banned : ServerSideCryptoBan.BANNED_METHOD_PATTERNS) {
                                    if (content.contains(banned)) {
                                        violations.append("\n  ")
                                                .append(file)
                                                .append(" contains: ")
                                                .append(banned);
                                    }
                                }
                            } catch (IOException e) {
                                throw new UncheckedIOException(e);
                            }
                        });
            }
        }

        if (!violations.isEmpty()) {
            fail("ServerSideCryptoBan violation detected:" + violations);
        }
    }

    @Test
    @DisplayName("AC-5: Server-side code must not contain AT signing key configuration")
    void shouldNotContainAtSigningKeyConfig() throws IOException {
        StringBuilder violations = new StringBuilder();

        String[] bannedConfigs = {"jwt-at-secret-hex", "at-secret", "AT_SECRET"};

        for (Path pkg : SERVER_PACKAGES) {
            Path dir = BACKEND_SRC.resolve(pkg);
            if (!Files.exists(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                files.filter(Files::isRegularFile)
                        .filter(f -> f.toString().endsWith(".java"))
                        .forEach(file -> {
                            try {
                                String content = Files.readString(file, StandardCharsets.UTF_8);
                                for (String banned : bannedConfigs) {
                                    if (content.contains(banned)) {
                                        violations.append("\n  ")
                                                .append(file)
                                                .append(" references: ")
                                                .append(banned);
                                    }
                                }
                            } catch (IOException e) {
                                throw new UncheckedIOException(e);
                            }
                        });
            }
        }

        if (!violations.isEmpty()) {
            fail("AT secret key reference detected - AT must be signed by device private key only:" + violations);
        }
    }
}
