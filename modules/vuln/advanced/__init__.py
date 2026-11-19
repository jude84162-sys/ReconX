# modules/vuln/advanced/__init__.py
"""ReconX advanced vulnerability scanners.

API/GraphQL, business-logic, deep-injection and cloud-exposure modules. All use
the shared engine in ``modules.utils.http_client`` for differential analysis
and WAF-evasion payload mutation.

Modules:
    graphql_scanner   introspection, batching, field suggestions
    api_fuzzer        swagger/openapi/Postman discovery + type mismatch
    mass_assignment   hidden fields and parameter pollution
    bola_mapper       two-account object-level authorization mapping
    race_condition    synchronized bursts for TOCTOU flaws
    deserialization   serialized objects in cookies/params/fields
    xxe_lfi           XXE and local file inclusion
    cloud_metadata    metadata SSRF + internal port discovery
    bucket_checker    S3/Azure/GCP bucket permissions
"""
