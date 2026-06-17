package de.bsi.secvisogram.csaf_cms_backend.mustache;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Behavioural unit tests for {@link JavascriptExporter#createHtml(String)} covering the
 * bug-fix acceptance criteria from the spec (AC#2 input-not-mutated, AC#3 no stdout pollution).
 *
 * <p>These tests deliberately stay on the public {@code createHtml} interface and do not reach
 * into the JS context internals.
 */
@SpringBootTest(properties = "csaf.document.templates.companyLogoPath=")
@ExtendWith(SpringExtension.class)
class JavascriptExporterInputMutationTest {

    /**
     * A minimal CSAF 2.0 advisory with a single vulnerability carrying a {@code scores} entry.
     * The renderer's preview step enriches the document with derived keys
     * (e.g. {@code max_base_score}, {@code notes_summary}); this fixture exercises that
     * enrichment so the mutation test is meaningful.
     */
    private static final String json = """
            {
              "document": {
                "category": "generic_csaf",
                "csaf_version": "2.0",
                "publisher": {
                  "category": "coordinator",
                  "name": "exccellent",
                  "namespace": "https://exccellent.de"
                },
                "title": "TestRSc",
                "notes": [
                  {
                    "category": "summary",
                    "text": "a document summary note"
                  }
                ],
                "tracking": {
                  "current_release_date": "2022-01-11T11:00:00.000Z",
                  "id": "exxcellent-2021AB123",
                  "initial_release_date": "2022-01-12T11:00:00.000Z",
                  "revision_history": [
                    {
                      "date": "2022-01-12T11:00:00.000Z",
                      "number": "0.0.1",
                      "summary": "Test rsvSummary"
                    }
                  ],
                  "status": "draft",
                  "version": "0.0.1"
                }
              },
              "vulnerabilities": [
                {
                  "title": "a vulnerability",
                  "notes": [
                    {
                      "category": "description",
                      "text": "a vulnerability description note"
                    }
                  ],
                  "scores": [
                    {
                      "cvss_v3": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                      },
                      "products": ["CSAFPID-0001"]
                    }
                  ]
                }
              ]
            }
            """;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private JavascriptExporter javascriptExporter;

    /**
     * AC#2: {@code createHtml} must not leak the renderer's preview enrichment back to the
     * caller's data. Because {@code createHtml} takes an immutable {@link String}, we prove the
     * stronger property the spec asks for: a fresh parse of the very same JSON, after the call,
     * contains none of the preview-added keys. (If the renderer ever mutated shared parsed state,
     * these keys would appear.)
     */
    @Test
    void createHtmlDoesNotLeakPreviewKeysIntoCallerInput() throws IOException {
        this.javascriptExporter.createHtml(json);

        final JsonNode root = MAPPER.readTree(json);
        final JsonNode document = root.at("/document");
        final JsonNode vulnerability = root.at("/vulnerabilities/0");

        // Document-level preview-added keys must not be present.
        assertThat(document.has("max_base_score"), is(false));
        assertThat(document.has("notes_summary"), is(false));
        assertThat(document.has("notes_details"), is(false));
        assertThat(document.has("notes_unknown"), is(false));

        // Vulnerability-level preview-added keys must not be present.
        assertThat(vulnerability.has("notes_summary"), is(false));
        assertThat(vulnerability.has("notes_description"), is(false));
        assertThat(vulnerability.has("remediations_vendor_fix"), is(false));
        assertThat(vulnerability.has("threats_exploit_status"), is(false));

        // The original, declared keys must still be exactly as supplied.
        assertThat(document.get("csaf_version").asText(), is("2.0"));
        assertThat(vulnerability.get("title").asText(), is("a vulnerability"));
    }

    /**
     * AC#3: no {@code print(...)} debug output is emitted to stdout during export. The old fork
     * printed the full advisory JSON and the document title; redirect {@link System#out} around
     * the call and assert none of that leaks out.
     */
    @Test
    void createHtmlDoesNotPolluteStdout() throws IOException {
        final PrintStream originalOut = System.out;
        final ByteArrayOutputStream captured = new ByteArrayOutputStream();
        final String html;
        try {
            System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
            html = this.javascriptExporter.createHtml(json);
        } finally {
            System.setOut(originalOut);
        }

        final String stdout = captured.toString(StandardCharsets.UTF_8);

        // The old debug output dumped the advisory's title and its JSON-ish body to stdout.
        assertThat(stdout, not(containsString("TestRSc")));
        assertThat(stdout, not(containsString("csaf_version")));
        assertThat(stdout, not(containsString("\"document\"")));
        assertThat(stdout, not(containsString("%%%")));

        // Sanity: the call still produced the rendered HTML (output went to the return value,
        // not to stdout).
        assertThat(html, containsString("<h1>"));
        assertThat(html, containsString("TestRSc"));
    }
}
