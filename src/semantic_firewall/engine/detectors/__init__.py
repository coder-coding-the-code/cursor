from semantic_firewall.engine.detectors.hidden_instruction import HiddenInstructionDetector
from semantic_firewall.engine.detectors.jailbreak import JailbreakDetector
from semantic_firewall.engine.detectors.malicious_structure import MaliciousStructureDetector
from semantic_firewall.engine.detectors.obfuscation import ObfuscationDetector
from semantic_firewall.engine.detectors.ontology_poisoning import OntologyPoisoningDetector
from semantic_firewall.engine.detectors.privilege_escalation import PrivilegeEscalationDetector
from semantic_firewall.engine.detectors.prompt_injection import PromptInjectionDetector
from semantic_firewall.engine.detectors.tool_abuse import ToolAbuseDetector

DEFAULT_DETECTORS = [
    PromptInjectionDetector(),
    JailbreakDetector(),
    HiddenInstructionDetector(),
    PrivilegeEscalationDetector(),
    ObfuscationDetector(),
    ToolAbuseDetector(),
    OntologyPoisoningDetector(),
    MaliciousStructureDetector(),
]
