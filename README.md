# whohk

whohk，linux下一款强大的应急响应工具

<a href="https://github.com/heikanet/whohk"><img alt="Release" src="https://img.shields.io/badge/python-3.x+-9cf"></a>
<a href="https://github.com/heikanet/whohk"><img alt="Release" src="https://img.shields.io/badge/whohk-1.1-ff69b4"></a>
<a href="https://github.com/heikanet/whohk"><img alt="Release" src="https://img.shields.io/badge/LICENSE-GPL-important"></a>
![GitHub Repo stars](https://img.shields.io/github/stars/heikanet/whohk?color=success)
![GitHub forks](https://img.shields.io/github/forks/heikanet/whohk)
![GitHub all release](https://img.shields.io/github/downloads/heikanet/whohk/total?color=blueviolet)  

在linux下的应急响应往往需要通过繁琐的命令行来查看各个点的情况，有的时候还需要做一些格式处理，这对于linux下命令不是很熟悉的人比较不友好。本工具将linux下应急响应中常用的一些操作给集合了起来，并处理成了较为友好的格式，只需要通过一个参数就能代替繁琐复杂的命令来实现对各个点的检查。

支持主流的Linux，包含centos、redhat、ubuntu、debian、opensuse。

## 使用指南
```
optional arguments:
  -h, --help            show this help message and exit
  -user                 用于查看系统可登录账户和空口令账户（无参数）
  -history              用于查看所有用户的敏感历史命令（无参数）
  -cron                 用于查看所有用户的定时任务（无参数）
  -ip                   用于查看外连ip（无参数）
  --pid 1234            用于定位进程物理路径（参数为pid号）
  --ssh-fip             用于查看ssh登录失败的ip和次数（无参数）
  --ssh-fuser           用于查看ssh登录失败的用户和次数（无参数）
  --ssh-sip             用于查看ssh登录成功的ip和次数（无参数）
  --ssh-sinfo           用于查看ssh登录成功的用户详情（无参数）
  --file-cron 7         用于查看系统各个级别定时任务目录中，n天内被修改的文件（参数为天数）
  --file-starup 7       用于查看系统启动项目录中，n天内被修改的文件（参数为天数）
  --file-os 7           用于查看系统重要目录中，n天内被修改的文件（参数为天数）
  --file-change /www 7 php
                        用于查看在n天内指定目录中指定后缀的被修改的文件（参数为物理路径、天数、后缀）
  --file-perm /www jsp 777
                        用于查看指定目录下指定后缀指定权限的文件（参数为物理路径、后缀、天数）
  --s-backdoor /home    用于检测指定路径下的恶意样本（参数为物理路径）
  --s-webshell /var/www
                        用于检测指定路径下的webshell（参数为物理路径）
```

## 细节

由于懒得重新截图，所以就直接放公众号之前发的图了
- whohk，一款强大的linux应急响应辅助工具：[点击跳转](https://mp.weixin.qq.com/s?__biz=MzIyNDkwNjQ5Ng==&mid=2247484224&idx=1&sn=616be624b7936abef282c5611f710a6a&chksm=e8069f2fdf71163973a712de55de80b042fb6224fa9179b4a655b5fe2e5be647f63d7f038e60&token=1653316416&lang=zh_CN#rd)

- [更新]Linux下应急响应工具whohk v1.1版本：[点击跳转](https://mp.weixin.qq.com/s?__biz=MzIyNDkwNjQ5Ng==&mid=2247485371&idx=1&sn=8f6a32e28bf06e100edcd9241a8923e4&chksm=e8069bd4df7112c28a416e740b6025982d1d4a920906f9e3aa2f6244c5a691af6cf9a96bb55d#rd)

- 如何打造一款自己的恶意样本检测工具：[点击跳转](https://mp.weixin.qq.com/s?__biz=MzIyNDkwNjQ5Ng==&amp;mid=2247484475&amp;idx=1&amp;sn=7180cb7a18335c71ef561f9ec468f601&amp;chksm=e8069854df7111425708634704d07832764f02545065717fd45424abb960938cbc121a417eb5&token=393884268&lang=zh_CN#rd)

## 碎碎念
- 2020-09-21 
>  在历次的Linux系统下应急中感受到了敲命令的繁琐，以及有些太长记不住的命令当着客户面去百度的尴尬，决定把Linux下应急检查的一些点的命令用工具来集合到一起。在这个工具之前其实还做过一个windows/Linux系统下的安全巡检小工具，但由于对我的工作意义不大，所以最后经过一顿操作，有了`whohk`这一款小工具。

- 2021-08-26
> 在过去的近一年里应急的次数不那么频繁了，基本无视这个工具。不过有一次登录公众号后，发现有一些粉丝私信提新功能以及反馈了一些问题（原谅我半年登一次公众号），所以这次根据之前的反馈，进行了一些更新。

- 2022-04-30
> 发现这个工具居然成为了我GitHub stars最多的一个项目，或许真的帮助到了一些人。
> 决定开源。代码写的很简单，也可以说比较烂，本次上传的是2021.08.26的版本，也是目前最新版（因为只要没有新的需求就不会更新，以及我~~没有时间~~懒也不会更新🐶）。
> 
> 不会摆烂。目前有一些新的想法，但是很模糊，大家有好的建议欢迎提issue。

## TODO
- [ ] 重构，代码写的优雅点
- [ ] Windows支持
- [ ] server端
- [ ] 多台主机数据聚合分析

## 交流

![](img/taixiayanshu.png)
![](img/wgpsec.png)


