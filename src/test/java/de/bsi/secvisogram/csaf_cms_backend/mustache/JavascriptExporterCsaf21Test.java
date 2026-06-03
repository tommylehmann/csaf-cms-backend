package de.bsi.secvisogram.csaf_cms_backend.mustache;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.StringUtils;

/**
 * CSAF 2.1 rendering and version-routing tests for {@link JavascriptExporter#createHtml(String)}.
 *
 * <p>Covers AC#4 (2.1 renders without error), AC#5 (2.1-specific fields present, header CVSS base
 * score derived from {@code metrics[].content.cvss_v3}) and AC#6 (missing {@code csaf_version}
 * routes to the 2.0 renderer).
 *
 * <p>Assertions prefer targeted {@code containsString} checks over a brittle full golden master:
 * the 2.0 golden tests ({@code JavascriptExporterTest}/{@code JavascriptExporterNoLogoTest})
 * remain the byte-for-byte gate for 2.0 output.
 */
@SpringBootTest(properties = "csaf.document.templates.companyLogoPath=")
@ExtendWith(SpringExtension.class)
class JavascriptExporterCsaf21Test {

    /** Distinctive CWE values rendered as {@code id:name:version} by the 2.1 template. */
    private static final String CWE_1_ID = "CWE-79";
    private static final String CWE_1_NAME = "Improper Neutralization of Input During Web Page Generation";
    private static final String CWE_2_ID = "CWE-89";
    private static final String CWE_2_NAME = "SQL Injection";
    private static final String DISCLOSURE_DATE = "2024-03-15T10:00:00.000Z";
    private static final String SHARING_GROUP_ID = "4150b693-2c64-4d8e-bf03-1234567890ab";
    private static final String SHARING_GROUP_NAME = "Trusted Partners Circle";
    private static final String CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
    private static final String CVSS_BASE_SCORE = "9.8";

    /**
     * A CSAF 2.1 advisory exercising the 2.1-specific shapes: {@code metrics[].content.cvss_v3}
     * (non-zero baseScore + vectorString), a {@code cwes} array with two entries, a
     * {@code disclosure_date}, a {@code sharing_group}, and a top-level {@code $schema}. The rest
     * is kept minimal but schema-plausible, reusing the shapes from the existing 2.0 fixtures.
     */
    private static final String json21 = """
            {
              "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
              "document": {
                "category": "generic_csaf",
                "csaf_version": "2.1",
                "publisher": {
                  "category": "coordinator",
                  "name": "exccellent",
                  "namespace": "https://exccellent.de"
                },
                "title": "TestRSc 2.1",
                "distribution": {
                  "tlp": {
                    "label": "WHITE"
                  },
                  "sharing_group": {
                    "id": "%s",
                    "name": "%s"
                  }
                },
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
              "product_tree": {
                "full_product_names": [
                  {
                    "product_id": "CSAFPID-0001",
                    "name": "Sample Product 1.0"
                  }
                ]
              },
              "vulnerabilities": [
                {
                  "title": "a 2.1 vulnerability",
                  "cwes": [
                    {
                      "id": "%s",
                      "name": "%s",
                      "version": "4.13"
                    },
                    {
                      "id": "%s",
                      "name": "%s",
                      "version": "4.13"
                    }
                  ],
                  "disclosure_date": "%s",
                  "product_status": {
                    "known_affected": ["CSAFPID-0001"]
                  },
                  "metrics": [
                    {
                      "products": ["CSAFPID-0001"],
                      "content": {
                        "cvss_v3": {
                          "baseScore": %s,
                          "vectorString": "%s"
                        }
                      }
                    }
                  ]
                }
              ]
            }
            """.formatted(
            SHARING_GROUP_ID, SHARING_GROUP_NAME,
            CWE_1_ID, CWE_1_NAME,
            CWE_2_ID, CWE_2_NAME,
            DISCLOSURE_DATE,
            CVSS_BASE_SCORE, CVSS_VECTOR);

    @Autowired
    private JavascriptExporter javascriptExporter;

    /** AC#4: rendering a 2.1 advisory must not throw. */
    @Test
    void createHtmlRendersCsaf21WithoutError() throws IOException {
        final String html = this.javascriptExporter.createHtml(json21);
        assertThat(html, containsString("<h1>"));
        assertThat(html, containsString("TestRSc 2.1"));
    }

    /** AC#5: the 2.1-specific fields are present in the rendered HTML. */
    @Test
    void createHtmlIncludesCsaf21Fields() throws IOException {
        final String html = this.javascriptExporter.createHtml(json21);

        // Both CWE entries, rendered as id:name(:version) by the {{#cwes}} block.
        assertThat(html, containsString(CWE_1_ID));
        assertThat(html, containsString(CWE_1_NAME));
        assertThat(html, containsString(CWE_2_ID));
        assertThat(html, containsString(CWE_2_NAME));

        // disclosure_date (2.1) renders under its own row, not the 2.0 "Release date".
        assertThat(html, containsString("Disclosure date:"));
        assertThat(html, containsString(DISCLOSURE_DATE));

        // sharing_group id + name.
        assertThat(html, containsString(SHARING_GROUP_ID));
        assertThat(html, containsString(SHARING_GROUP_NAME));
    }

    /**
     * AC#5: the document header CVSS base score is derived from
     * {@code metrics[].content.cvss_v3.baseScore} (the 2.1 data shape), and the per-product status
     * row reflects the metric's vector string + base score.
     */
    @Test
    void createHtmlHeaderCvssBaseScoreReflectsMetrics() throws IOException {
        final String html = this.javascriptExporter.createHtml(json21);

        // Document header line populated from document.max_base_score = max over metrics cvss_v3.
        assertThat(html, containsString("CVSSv3.1 Base Score: " + CVSS_BASE_SCORE));

        // Product status row picks up the metric's vector string and base score for the product.
        // Mustache HTML-escapes the '/' separators to "&#x2F;" (same escaping the 2.0 golden tests
        // show for URLs), so assert on the escaped form.
        final String escapedVector = CVSS_VECTOR.replace("/", "&#x2F;");
        assertThat(html, containsString(escapedVector));
        assertThat(html, containsString("<td>" + CVSS_BASE_SCORE + "</td>"));
    }

    /**
     * AC#6: an advisory with no {@code csaf_version} routes to the 2.0 renderer and produces output
     * equivalent to the same advisory with an explicit {@code "csaf_version": "2.0"}.
     */
    @Test
    void missingCsafVersionRoutesTo20() throws IOException {
        final String html20 = this.javascriptExporter.createHtml(json20("2.0"));
        final String htmlNoVersion = this.javascriptExporter.createHtml(json20(null));

        // Both must carry the 2.0-only markers (single {{#cwe}} block label + Release date row).
        assertThat(html20, containsString("CWE-20:Improper Input Validation"));
        assertThat(html20, containsString("Release date:"));
        assertThat(htmlNoVersion, containsString("CWE-20:Improper Input Validation"));
        assertThat(htmlNoVersion, containsString("Release date:"));

        // Neither must render the 2.1-only Disclosure date row.
        assertThat(html20, is(htmlNoVersion));
        assertThat(StringUtils.trimAllWhitespace(htmlNoVersion),
                is(StringUtils.trimAllWhitespace(html20)));
    }

    /**
     * A minimal CSAF 2.0 advisory using 2.0 shapes (single {@code cwe}, {@code scores},
     * {@code release_date}). {@code csafVersion} is omitted entirely when {@code null}.
     */
    private static String json20(final String csafVersion) {
        final String versionLine = csafVersion == null
                ? ""
                : "    \"csaf_version\": \"" + csafVersion + "\",\n";
        return """
                {
                  "document": {
                    "category": "generic_csaf",
                %s    "publisher": {
                      "category": "coordinator",
                      "name": "exccellent",
                      "namespace": "https://exccellent.de"
                    },
                    "title": "TestRSc",
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
                      "title": "a 2.0 vulnerability",
                      "cwe": {
                        "id": "CWE-20",
                        "name": "Improper Input Validation"
                      },
                      "release_date": "2024-01-01T00:00:00.000Z",
                      "scores": [
                        {
                          "cvss_v3": {
                            "baseScore": 5.5,
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                          },
                          "products": ["CSAFPID-0001"]
                        }
                      ]
                    }
                  ]
                }
                """.formatted(versionLine);
    }
}
