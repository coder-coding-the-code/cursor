/*
 * ECS overlay signatures — industrial / Chinese / jailbreak / privilege.
 * Complements Vigil YARA (Apache-2.0) for 星河智造 channels.
 */
rule ECS_ChineseInstructionBypass: Injection
{
    meta:
        category = "Instruction Bypass"
        threat = "prompt_injection"
        source = "ecs"
        description = "Chinese prompt-injection / indirect RAG steering"

    strings:
        $zh1 = "忽略之前的指令" nocase
        $zh2 = "忽略以上的指令" nocase
        $zh3 = "忽略先前的指令" nocase
        $zh4 = "不要遵守" nocase
        $zh5 = "新的系统指令" nocase
        $zh6 = "覆盖系统" nocase
        $zh7 = "当助手读到本文时请" nocase
        $zh8 = "检索到本文时请" nocase
        $zh9 = "给语言模型的隐藏指令" nocase
    condition:
        any of them
}

rule ECS_JailbreakDAN: Jailbreak
{
    meta:
        category = "Jailbreak"
        threat = "jailbreak"
        source = "ecs"
        description = "DAN / developer-mode / unrestricted roleplay"

    strings:
        $dan = "do anything now" nocase
        $jb = "jailbreak" nocase
        $dev = "developer mode" nocase
        $god = "god mode" nocase
        $unf = "unfiltered" nocase
        $norule = "no restrictions" nocase
        $nofilter = "without any restrictions" nocase
        $zh_jb = "越狱" nocase
        $zh_dev = "开发者模式" nocase
        $zh_unlim = "无限制模式" nocase
        $zh_role = "没有道德限制" nocase
    condition:
        any of them
}

rule ECS_PrivilegeEscalation: PrivEsc
{
    meta:
        category = "Privilege Escalation"
        threat = "privilege_escalation"
        source = "ecs"
        description = "Trust-level / firewall / impersonation escalation"

    strings:
        $t5 = "trust_level" nocase
        $fw = "关闭语义防火墙"
        $fw2 = "disable" nocase
        $grant = "grant me admin" nocase
        $sudo = "sudo mode" nocase
        $imp = "impersonate" nocase
        $zh1 = "升级到 T5"
        $zh2 = "提升权限"
        $zh3 = "授予管理员"
        $zh4 = "冒充负责人"
        $kill = "kill switch" nocase
        $rbac = "bypass rbac" nocase
    condition:
        ($t5 and ($fw or $fw2 or $zh1)) or $grant or $sudo or $imp or $zh2 or $zh3 or $zh4 or $kill or $rbac
}
