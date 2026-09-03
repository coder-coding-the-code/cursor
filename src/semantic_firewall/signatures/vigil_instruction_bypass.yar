/*
 * Vendored from Vigil (deadbits/vigil-llm) data/yara/instruction_bypass.yar
 * Copyright 2023 Adam M. Swanda
 * Licensed under Apache License 2.0
 *
 * Modification: added case-insensitive flag so folded / lowercased
 * payloads still match (ECS semantic firewall canonicalize stage).
 */
rule InstructionBypass: Injection
{
    meta:
        category = "Instruction Bypass"
        threat = "prompt_injection"
        source = "vigil-llm"
        description = "Detects phrases used to ignore, disregard, or bypass instructions."
        author = "Adam M. Swanda"

    strings:
        $bypass_phrase = /(Ignore|Disregard|Skip|Forget|Neglect|Overlook|Omit|Bypass|Pay no attention to|Do not follow|Do not obey)\s*(prior|previous|preceding|above|foregoing|earlier|initial)?\s*(content|text|instructions|instruction|directives|directive|commands|command|context|conversation|input|inputs|data|message|messages|communication|response|responses|request|requests)\s*(and start over|and start anew|and begin afresh|and start from scratch)?/i
    condition:
        $bypass_phrase
}
