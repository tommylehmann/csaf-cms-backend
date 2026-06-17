package de.bsi.secvisogram.csaf_cms_backend.mustache;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.annotation.Nonnull;
import org.apache.commons.codec.binary.Base64;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.io.IOAccess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;

/**
 * Create Html String from a mustache template file and Json Input File
 */
@Service
public class JavascriptExporter {

    private static final Logger LOG = LoggerFactory.getLogger(JavascriptExporter.class);

    /** The only explicitly recognized CSAF version; anything else falls back to 2.0. */
    private static final String CSAF_VERSION_2_1 = "2.1";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @org.springframework.beans.factory.annotation.Value("${csaf.document.templates.companyLogoPath}")
    private String companyLogoPath;

    /**
     * Create an HTML export from the provided advisory document (as JSON)
     *
     * @param advisoryJson the advisory that should be exported (in JSON format)
     * @return the HTML document as a String
     * @throws IOException on any error regarding disk write/read
     */
    public String createHtml(@Nonnull final String advisoryJson) throws IOException {

        // Route by the CSAF version declared in the advisory. The version selects
        // the per-version DocumentEntity_*.mjs and Template_*.html; Script.mjs and
        // mustache.min.js are version-independent (see ADR-0002). Logo injection
        // happens in Script.mjs and is version-independent (see createLogoJson()).
        final boolean isCsaf21 = isCsaf21(advisoryJson);
        final String documentEntityResource =
                isCsaf21 ? "DocumentEntity_2_1.mjs" : "DocumentEntity_2_0.mjs";
        final String templateResourceName = isCsaf21 ? "Template_2_1.html" : "Template_2_0.html";
        LOG.info("Exporting advisory as HTML using CSAF version {}", isCsaf21 ? CSAF_VERSION_2_1 : "2.0");

        // Script.mjs statically imports "DocumentEntity.mjs", so the selected
        // per-version entity must be copied into the Context working directory
        // under that fixed name.
        final String documentEntityScript = "DocumentEntity.mjs";
        final Path tempDir = Files.createTempDirectory("mustache");
        LOG.info("Creating temporary directory: {}", tempDir.toFile().getAbsolutePath());
        final Path tempDocFile = tempDir.resolve(documentEntityScript);
        LOG.info("Creating temporary doc file: {}", tempDocFile.toFile().getAbsolutePath());

        try (final InputStream in = JavascriptExporter.class.getResourceAsStream(documentEntityResource)) {
            Files.write(tempDocFile, in.readAllBytes());
        }
        final var jsContext = Context.newBuilder("js")
                .allowExperimentalOptions(true)
                .allowIO(IOAccess.ALL)
                .option("js.esm-eval-returns-exports", "true")
                .currentWorkingDirectory(tempDir)
                .build();

        try (final InputStream templateResource = JavascriptExporter.class.getResourceAsStream(templateResourceName);
             final InputStream mustacheResource = JavascriptExporter.class.getResourceAsStream("mustache.min.js");
             final InputStream scriptResource = JavascriptExporter.class.getResourceAsStream("Script.mjs")) {
            final var template = new String(templateResource.readAllBytes(), StandardCharsets.UTF_8);
            final var mustacheSource = Source.newBuilder("js", this.createResourceReader(mustacheResource), "mustache.js")
                    .build();
            jsContext.eval(mustacheSource);
            final var scriptSource = Source.newBuilder("js", createResourceReader(scriptResource), "Script.mjs")
                    .mimeType("application/javascript+module")
                    .build();
            final Value scriptResult = jsContext.eval(scriptSource);
            final Value renderFunction = scriptResult.getMember("renderWithMustache");
            final Object result = renderFunction.execute(template, advisoryJson, createLogoJson());
            return result.toString();
        } finally {
            try {
                LOG.info("Delete temporary directory: {}", tempDir.toFile().getAbsolutePath());
                FileSystemUtils.deleteRecursively(tempDir);
            }   catch (IOException ex) {
                LOG.warn("Failed to delete temporary directory: {}", tempDir.toFile().getAbsolutePath(), ex);
            }
        }
    }

    private Reader createResourceReader(@Nonnull final InputStream input) {
        return new InputStreamReader(input, StandardCharsets.UTF_8);
    }

    /**
     * Determine whether the advisory should be rendered with the CSAF 2.1 renderer.
     * Returns {@code true} only when {@code /document/csaf_version} equals exactly
     * {@code "2.1"}; missing, unparsable, or any other value routes to 2.0.
     *
     * @param advisoryJson the advisory in JSON format
     * @return {@code true} if the 2.1 renderer should be used, {@code false} otherwise
     */
    private boolean isCsaf21(@Nonnull final String advisoryJson) {
        try {
            final JsonNode root = OBJECT_MAPPER.readTree(advisoryJson);
            final JsonNode versionNode = root.at("/document/csaf_version");
            return versionNode.isTextual() && CSAF_VERSION_2_1.equals(versionNode.asText());
        } catch (final IOException ex) {
            LOG.warn("Could not parse advisory JSON to read /document/csaf_version; defaulting to CSAF 2.0", ex);
            return false;
        }
    }

    private String createLogoJson() throws IOException {
        if (this.companyLogoPath == null || "".equals(this.companyLogoPath)) {
            LOG.info("The company logo path was not set, export result will not contain a logo.");
            return null;
        }
        final Path logoPath = Path.of(this.companyLogoPath);
        final MediaType logoMediaType = determineMediaTypeOfLogo(logoPath);
        final byte[] encoded = Base64.encodeBase64(Files.readAllBytes(logoPath));
        final String data = new String(encoded, StandardCharsets.US_ASCII);
        final ObjectNode node = new ObjectMapper().createObjectNode();
        node.put("mediaType", logoMediaType.toString());
        node.put("data", data);
        return node.toString();
    }

    static MediaType determineMediaTypeOfLogo(@Nonnull final Path path) {
        final Path filename = path.getFileName();
        if (filename != null) {
            final String fileName = filename.toString().toLowerCase();
            if (fileName.endsWith(".png")) {
                return MediaType.IMAGE_PNG;
            } else if (fileName.endsWith(".jpg") || fileName.endsWith(".jpeg")) {
                return MediaType.IMAGE_JPEG;
            }
            throw new IllegalArgumentException("Unknown company logo format: " + fileName);
        }
        throw new IllegalArgumentException("Got empty path");
    }
}
