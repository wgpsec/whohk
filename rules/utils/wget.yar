rule wget {
    meta:
        author = "yiansec"
    strings:
        $url_regex = /wget https?:\/\// wide ascii
    condition:
        $url_regex
}