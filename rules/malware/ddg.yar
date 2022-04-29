// ddg脚本通配规则
rule linux_miner_ddg_script_gen
{
    meta:
        description = "ddg shell script general"
        author = "G4rb3n"
        reference = "https://blog.netlab.360.com/ddg-a-mining-botnet-aiming-at-database-server"
        date = "2020-5-13"

   strings:
      $s1 = "/i.sh"
      $s2 = "/ddgs"

      $c1 = "/var/spool/cron/root"
      $c2 = "crontab -"

   condition:
      ( filesize < 50KB ) and ( all of ($s*) ) and ( 1 of ($c*) )
}

// v5000以上版本的规则
rule linux_miner_ddg_script_v5
{
    meta:
      description = "ddg shell script v5000+"
      author = "G4rb3n"
      reference = "https://blog.netlab.360.com/ddg-upgrade-to-new-p2p-hybrid-model"
      date = "2020-5-13"
      url = "http://67.205.168.20:8000/i.sh"
      md5_v5023 = "FE0D7BCF06779EF0CC6702FBB7C330E7"
      md5_v5019 = "D6F402F6DCB75EA1A81A7C596CDA50C5"

   strings:
      $s1 = "/i.sh"
      $s2 = /\/50[0-9]{2}\/ddgs.+/

      $c1 = "/var/spool/cron/root"
      $c2 = "crontab -"

   condition:
        ( filesize < 50KB ) and ( all of ($s*) ) and ( 1 of ($c*) )
}