// StartMiner脚本通配规则
rule linux_miner_rainbowminer_script_gen
{
    meta:
        description = "rainbowminer script general"
        author = "G4rb3n"
        reference = "https://mp.weixin.qq.com/s/KUK2hW7oRA2hN_cJ5QaYUA"
        date = "2020-5-21"

   strings:
      $s1 = "=\"/lib64/"
      $s2 = "pdflushType=\""
      $s3 = "kthreadds"
      $s4 = "processhider"
      $s5 = "paDKiUwmHNUSW7E1S18Cl"    // ssh公钥片段
      $s6 = "cron.py"
      $s7 = "/pdflushs"
      
      $x1 = "Rainbow66"
      $x2 = "47.106.187.104"

   condition:
      ( filesize < 50KB ) and ( ( 4 of ($s*) ) or ( 1 of ($x*) ) )
}