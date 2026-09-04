# Input validation only: a nonzero digest does not prove that its evidence
# exists or that privileged R2 validation passed. Consume with jq --slurp.
def evidence_digest:
    if type == "string" then
        length == 64 and test("^[0-9a-f]{64}$") and . != ("0" * 64)
    else false end;

length == 1 and
(.[0] | try (
    type == "object" and
    .schema == "nftfw.r2-attestation.v1" and
    .status == "R2_PASSED_TAG_BUILD_AUTHORIZED" and
    .target_version == $version and .git_commit == $commit and
    .publication_authorized == false and .deployment_authorized == false and
    .privileged_evidence.package_boot_network_docker_ovpn == "PASS" and
    (.privileged_evidence_manifest_sha256 | evidence_digest) and
    (.stage_r_candidate_comparison_sha256 | evidence_digest)
) catch false)
