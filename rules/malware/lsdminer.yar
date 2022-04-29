// LSDMiner脚本通配规则
rule linux_miner_lsdminer_script_gen
{
    meta:
        description = "lsdminer script general"
        author = "G4rb3n"
        reference = "https://www.anquanke.com/post/id/193116"
        date = "2020-5-21"

   strings:
      $s1 = "hwlh3wlh44lh"
      $s2 = "Circle_MI"
      $s3 = "thyrsi.com"
      $s4 = "img.sobot.com"
      $s5 = "cdn.xiaoduoai.com"
      $s6 = "res.cloudinary.com"
      $s7 = "pastebin.com"
      $s8 = "user-images.githubusercontent.com"

   condition:
      ( filesize < 50KB ) and ( 4 of ($s*) )
}