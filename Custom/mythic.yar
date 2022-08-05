
rule MythicC2
{
    meta:
        created  = "08/04/2022"
        modified = "08/04/2022"
        author   = "@lum8rjack"

    strings:
        $one   = "github.com/its-a-feature" nocase ascii
        $two   = "Cody Thomas" nocase ascii
        $three = "@its_a_feature" nocase ascii
        $four  = "github.com/MythicAgents" nocase ascii
        $five  = "Mythic/agent_code" nocase ascii

    condition:
        any of them
}

rule MythicC2_Apfell_Agent
{
    meta:
        created  = "08/04/2022"
        modified = "08/04/2022"
        author   = "@lum8rjack"

    strings:
        $one   = "apfell.user" ascii
        $two   = "apfell.fullName" ascii
        $three = "apfell.ip" ascii
        $four  = "apfell.host" ascii

    condition:
        any of them
}

rule MythicC2_Merlin_Agent
{
    meta:
        created  = "08/04/2022"
        modified = "08/04/2022"
        author   = "@lum8rjack"

    strings:
        $one   = "github.com/Ne0nd0g/merlin-agent" ascii
        $two   = "convertToMerlinMessage" ascii
        $three = "golang.org" nocase ascii

    condition:
        ($one and $three) or ($two and $three)
}

rule MythicC2_Poseidon_Agent
{
    meta:
        created  = "08/04/2022"
        modified = "08/04/2022"
        author   = "@lum8rjack"

    strings:
        $one   = "github.com/MythicAgents/poseidon" nocase ascii
        $two   = "poseidon.go" nocase ascii
        $three = "golang.org" nocase ascii

    condition:
        ($one and $three) or ($two and $three)
}

rule MythicC2_Tetanus_Agent
{
    meta:
        created  = "08/04/2022"
        modified = "08/04/2022"
        author   = "@lum8rjack"

    strings:
        $one   = "github.com/MythicAgents/tetanus" nocase ascii
        $two   = "MythicFileRm" nocase ascii
        $three = "root/.cargo/registry/src/github.com" nocase ascii

    condition:
        ($one and $three) or ($two and $three)
}
