rule TestMalwareRule
{
    meta:
        description = "This is a test rule for YARA integration"
        author = "Antigravity"
    strings:
        $string1 = "MALICIOUS_TEST_PAYLOAD_12345"
    condition:
        $string1
}
