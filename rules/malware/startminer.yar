// StartMiner脚本通配规则
rule linux_miner_startminer_script_gen
{
    meta:
        description = "startminer script general"
        author = "G4rb3n"
        reference = "https://s.tencent.com/research/report/978.html"
        date = "2020-5-20"

   strings:
      $s1 = "echo \"P OK\""
      $s2 = "echo \"T DIR $DIR\""
      $s3 = "echo \"No md5sum\""
      $s4 = "echo \"P NOT EXISTS\""
      $s5 = "case $sum in"
      
      $x1 = "f2=\""
      $x2 = "downloadIfNeed()"
      $x3 = "judge()"
      $x4 = "judge2()"
      $x5 = "start.jpg"

      $c1 = "jukesxdbrxd.xyz"
      $c2 = "37.44.212.223"
      $c3 = "107.189.11.170"

   condition:
      ( filesize < 50KB ) and ( ( 4 of ($s*) ) and ( ( 2 of ($x*) ) or ( 1 of ($c*) ) ) )
}

