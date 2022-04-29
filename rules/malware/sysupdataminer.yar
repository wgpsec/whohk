// SysUpdataMiner脚本通配规则
rule linux_miner_sysupdataminer_script_gen
{
    meta:
        description = "sysupdataminer script general"
        author = "G4rb3n"
        reference = "https://www.freebuf.com/articles/system/172987.html"
        date = "2020-6-4"

   strings:
      $s1 = "miner_url"
      $s2 = "miner_size"
      $s3 = "sh_url"
      $s4 = "config_url"
      $s5 = "config_size"
      $s6 = "scan_url"
      $s7 = "scan_size"
      $s8 = "watchdog_url"
      $s9 = "watchdog_size"
      
      $x1 = "/etc/update.sh"
      $x2 = "/etc/sysupdate"
      $x3 = "/etc/networkservice"
      $x4 = "/usr/bin/cur" fullword ascii
      $x5 = "/usr/bin/wge" fullword ascii

      $c1 = "185.181.10.234"
      $c2 = "de.gsearch.com.de"
      $c3 = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC9WKiJ7yQ6HcafmwzDMv1RKxPdJI"

   condition:
      ( filesize < 50KB ) and ( ( ( 3 of ($s*) ) or ( 2 of ($x*) ) ) and ( 2 of ($c*) ) )
}