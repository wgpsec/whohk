// TeamTNT脚本通配规则
rule linux_miner_teamtnt_script_gen
{
    meta:
        description = "teamtnt shell script general"
        author = "G4rb3n"
        reference = "https://x.threatbook.cn/nodev4/vb4/article?threatInfoID=2813"
        date = "2020-8-8"
        md5_2008 = "BE5B1BE30CF430AF6F76776FEBE805F2"
        md5_2009 = "856109FAFF327638BA3A8EC5800E988C"

   strings:
      $s1 = "LDR=\"wget -q -O -\""
      $s2 = "LDR=\"curl\""
      $s3 = "echo \"cron good\""
      $s4 = "echo \"setup cron\""
      $s5 = "downloadxmin()"
      $s6 = "startxmin()"
      $s7 = "setupmyapps()"
      $s8 = "loadthisfile()"
      $s9 = "uploadthersa()"
      $s10 = "getsomelanssh()"
      $s11 = "localgo()"

      $c1 = "85.214.149.236"

   condition:
      ( filesize < 10KB ) and ( 2 of ($s*) ) and ( 1 of ($c*) )
}