package com.newrelic.agent.security.instrumentator.utils;

public interface INRSettingsKey {
    String SECURITY_POLICY_VULNERABILITY_SCAN_ENABLE = "security.policy.vulnerabilityScan.enabled";
    String SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_ENABLE = "security.policy.vulnerabilityScan.iastScan.enabled";
    String SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_INTERVAL = "security.policy.vulnerabilityScan.iastScan.probing.interval";
    String SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_BATCH_SIZE = "security.policy.vulnerabilityScan.iastScan.probing.batchSize";
    String SECURITY_POLICY_PROTECTION_MODE_ENABLE = "security.policy.protectionMode.enabled";
    String SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ENABLE = "security.policy.protectionMode.ipBlocking.enabled";
    String SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ATTACKER_IP_BLOCKING = "security.policy.protectionMode.ipBlocking.attackerIpBlocking";
    String SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_IP_DETECT_VIA_XFF = "security.policy.protectionMode.ipBlocking.ipDetectViaXFF";
    String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_ENABLE = "security.policy.protectionMode.apiBlocking.enabled";
    String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ALL_APIS = "security.policy.protectionMode.apiBlocking.protectAllApis";
    String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_KNOWN_VULNERABLE_APIS = "security.policy.protectionMode.apiBlocking.protectKnownVulnerableApis";
    String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ATTACKED_APIS = "security.policy.protectionMode.apiBlocking.protectAttackedApis";
    String SECURITY_DETECTION_DISABLE_RCI = "security.detection.disable_rci";
    String SECURITY_DETECTION_DISABLE_RXSS = "security.detection.disable_rxss";
    String SECURITY_DETECTION_DISABLE_DESERIALIZATION = "security.detection.disable_deserialization";

    String SECURITY_POLICY_ENFORCE = "security.policy.enforce";

    String NR_ENTITY_GUID = "entity.guid";
    String AGENT_RUN_ID = "agent_run_id";
    String HOSTNAME = "hostname";

    String AGENT_RUN_ID_LINKING_METADATA = "agentRunId";
}
