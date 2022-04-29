// SkipMap脚本通配规则
rule linux_miner_skipmap_script_gen
{
    meta:
        description = "skipmap shell script general"
        author = "G4rb3n"
        reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload"
        date = "2020-8-7"

   strings:
      $s1 = "chmod +x /var/lib/"
      $s2 = "/bin/get"
      $s3 = "/bin/cur"

      $c1 = "pm.ipfswallet.tk"
      $c2 = "a.powerofwish.com"

   condition:
      ( filesize < 10KB ) and ( all of ($s*) ) and ( 1 of ($c*) )
}