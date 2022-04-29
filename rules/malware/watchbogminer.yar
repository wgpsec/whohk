// WatchBogMiner脚本通配规则
rule linux_miner_watchbogminer_script_gen
{
    meta:
        description = "watchbogminer shell script general"
        author = "G4rb3n"
        reference = "https://s.tencent.com/research/report/1056.html"
        date = "2020-8-17"

   strings:
      $s1 = "pastebin.com"
      $s2 = "kill_miner_proc()"
      $s3 = "gettarfile()"
      $s4 = "base -d"

      $c1 = "UhUmR517"
      $c2 = "/JavaUpdates"
      $c3 = "tmpdropoff"

   condition:
      ( filesize < 50KB ) and ( 2 of ($s*) ) and ( 2 of ($c*) )
}