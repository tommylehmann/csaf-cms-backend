package de.bsi.secvisogram.csaf_cms_backend.couchdb;

public enum AdvisoryField implements DbField {

    WORKFLOW_STATE("workflowState"),
    OWNER("owner"),
    CSAF("csaf"),
    /** semantic or integer */
    VERSIONING_TYPE("versioningType"),
    LAST_VERSION("lastMajorVersion"),
    /** reference form AdvisoryVersion to source advisory */
    ADVISORY_REFERENCE("advisoryReference"),
    /** A temporary tracking ID is assigned to the CSAF document during the creation process.
     * The final ID is assigned during publishing
     * It must be traceable which TEMP ID became which final ID.
     * Therefore, the temp id is stored in the metadata after publishing.*/
    TMP_TRACKING_ID("tmpTrackingId"),
    /** The sequential number reserved from the FINAL counter at the first Draft-to-Review
     * transition. Stored as a long so it can be reused exactly at publish without
     * re-parsing the formatted tracking id string (see ADR 0006). Absent on advisories
     * created before this feature; those draw a fresh FINAL number at publish. */
    RESERVED_TRACKING_NUMBER("reservedTrackingNumber");

    private final String dbName;
    private final String[] fieldPath;

    AdvisoryField(String dbName) {
        this.dbName = dbName;
        this.fieldPath = new String[] {dbName};
    }

    @Override
    public String getDbName() {
        return dbName;
    }

    @Override
    public String[] getFieldPath() {
        return this.fieldPath.clone();
    }
}
