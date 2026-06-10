# Assay coverage matrix

31 frozen tasks. Mode A = MCP server under test; Mode B = agent under test. Oracle `canary` = structural-zero-FP cryptographic proof. Mappings are rendered from the engine's verified crosswalk, no id is hand-copied.

| ID | Task | Mode | Oracle | OWASP MCP | Adversa-25 | OWASP ASI | MITRE ATLAS |
|----|------|------|--------|------|------|------|------|
| M1 | Tool-description poisoning | B | canary | MCP03 | #3 | ASI02, ASI01 | AML.T0110, AML.T0051.001 |
| M2 | Line jumping (listed-but-uncalled) | B | canary | MCP06, MCP03 | #1, #3 | ASI01, ASI02 | AML.T0110 |
| M3 | Indirect injection via tool result | B | canary | MCP06, MCP10 | #1, #18 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| M4 | Cross-server tool shadowing | B | canary | MCP03, MCP10 | #17, #12 | ASI02, ASI01 | AML.T0110, AML.T0086 |
| M5 | Rug pull (post-approval mutation) | B | canary | MCP03 | #14 | ASI04, ASI02 | AML.T0110, AML.T0051.001 |
| M6 | Param injection (cmd/path/SQL) | A | behavioral | MCP05 | #2, #10, #21 | ASI05, ASI02 | AML.T0050 |
| M7 | Confused deputy / token passthrough | B | canary | MCP01, MCP07 | #6, #9 | ASI03, ASI02 | AML.T0086, AML.T0051.001 |
| M8 | Excessive agency / scope creep | B | behavioral | MCP02, MCP03 | #19 | ASI03, ASI02 | AML.T0110 |
| M9 | Destructive invocation, unconfirmed | B | behavioral | MCP06 | #19 | ASI02 | AML.T0110 |
| M10 | Secret exfiltration (lethal trifecta) | B | canary | MCP01 | #8 | ASI02 | AML.T0086, AML.T0057 |
| M11 | Sampling/createMessage abuse | B | canary | MCP10, MCP06 | #1 | ASI01, ASI09 | AML.T0024, AML.T0057 |
| M12 | Backdoored third-party tool | B | canary | MCP04 | #15 | ASI04 | AML.T0010, AML.T0086 |
| M13 | Full schema poisoning | B | canary | MCP03 | #11 | ASI02, ASI01 | AML.T0110 |
| M14 | Stored/deferred memory poisoning | B | canary | MCP10 | #18 | ASI06, ASI01 | AML.T0051.001, AML.T0086 |
| M15 | Inter-agent prompt infection | B | canary | MCP06 | #1 | ASI07, ASI01 | AML.T0051.001 |
| M16 | Runaway recursive tool calls | B | behavioral | MCP06 | - | ASI08 | AML.T0029 |
| M17 | DNS rebinding (no Origin check) | A | protocol | MCP07 | #13 | ASI03 | AML.T0049 |
| M18 | Unauthenticated server exposure | A | protocol | MCP07, MCP10 | #5 | ASI03 | AML.T0049 |
| M19 | Source->sink capability chain | B | canary | MCP01, MCP06 | #1 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| M20 | Visual / image-channel injection | B | canary | MCP06, MCP10 | #1 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| M21 | STAC temporal intent-splitting | B | canary | MCP06 | #1 | ASI01, ASI02 | AML.T0086, AML.T0054 |
| M22 | TOCTOU result swap | B | canary | MCP03 | #14, #18 | ASI04, ASI02 | AML.T0110, AML.T0051.001 |
| M23 | Cross-tenant data exposure | B | canary | MCP10, MCP07 | #25 | ASI03, ASI02 | AML.T0057, AML.T0086 |
| M24 | Rules/config-file injection | B | canary | MCP06, MCP03 | #7, #23 | ASI04, ASI01 | AML.T0110, AML.T0051.001 |
| M25 | RAG passage poisoning | B | canary | MCP10, MCP06 | #18, #1 | ASI06, ASI01 | AML.T0070, AML.T0051.001, AML.T0086 |
| OBF | Obfuscated-channel tool poisoning | B | canary | MCP03 | #1, #3 | ASI02, ASI01 | AML.T0110, AML.T0051.001 |
| M26 | Image-result tool poisoning (multimodal) | B | canary | MCP06, MCP10 | #1, #18 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| M27 | Cross-modal capability chain (vision->network) | B | canary | MCP01, MCP06 | #1 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| M28 | Steganographic chart canary (alt-text) | B | canary | MCP06, MCP10 | #1, #18 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| M29 | Multimodal rug-pull on image resource | B | canary | MCP03, MCP10 | #14, #18 | ASI04, ASI02 | AML.T0110, AML.T0051.001 |
| M30 | QR-code exfil in tool-returned image | B | canary | MCP10, MCP06 | #1, #18 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
