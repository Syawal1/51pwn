Twitter: [@Hktalent3135773](https://twitter.com/intent/follow?screen_name=Hktalent3135773)
[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=myhktools%20-%20Automated%20Pentest%20Recon%20Scanner%20%40Hktalent3135773&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2Fhktalent%2Fmyhktools)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773)
# 51pwn

## get country ip lists for nmap

```
mkdir csv;cd csv
wget https://www.nirsoft.net/countryip/index.html

cat index.html|grep -Eo '<td><a href="([^"]+)"'|sed -E 's/<td><a href="|"|\.html//g'|sort -u|uniq|xargs -I % bash -c 'echo %.csv;wget -O %.csv -c https://www.nirsoft.net/countryip/%.csv'

rm index.html
cd ..

```

# Bash命令获取国内所有SRC清单
```
mkdir SRC;cd SRC
wget -O src-list.txt  https://www.anquanke.com/src
cat src-list.txt|grep -Eo "(\/src\/[0-9]+)"|sort -u|uniq >src-list1.txt
rm src-list1.txt   src-list.txt
ls|xargs -I % bash -c "cat %|grep -Eo '<title>[^-]+-'|sed -E 's/<title>|-/ /g';grep -Eo '<a .*? href=\"http[^\"]+\">([^<]+)<\/a>' %|head -n 2|tail -n 1|sed -E 's/<[^>]+>//g'"
rm -rf *
```
	1)	 摩拜安全: https://security.mobike.com/user.php?m=user&amp;c=login&amp;a=index
	2)	 58SRC: https://security.58.com/
	3)	 OPPO安全应急响应中心: https://security.oppo.com/add.jsp
	4)	 宜信安全应急响应中心: https://security.creditease.cn/bugReport.html
	5)	 瓜子SRC: https://security.guazi.com
	6)	 DVP: https://dvpnet.io/
	7)	 微贷安全应急响应中心: https://sec.weidai.com.cn/user.php?m=User&amp;c=Login&amp;a=index
	8)	 快手安全中心: https://security.kuaishou.com/#/submit
	9)	 顺丰SRC: http://sfsrc.sf-express.com/submitBug
	10)	 isrc iTutorGroup: https://sec.tutorabc.com.cn
	11)	 智联招聘SRC: https://src.zhaopin.com/#/submitvul
	12)	 BUGX: https://www.bugx.io/
	13)	 东方财富SRC: https://passport2.eastmoney.com/pub/login?backurl=https%3A//se//A//security.eastmoney.com/checklogin/Oj2EK64eudkAwPvb8whTTvUWqkDW87hPs3tcMijf
	14)	 微众银行安全应急响应中心: https://security.webank.com/report/add
	15)	 字节跳动安全中心: https://security.bytedance.com/submit
	16)	 去哪儿安全应急响应中心: https://security.qunar.com/report.php
	17)	 安全狗漏洞响应中心: http://security.safedog.cn/report.html
	18)	 融360安全应急响应中心: https://security.rong360.com/#/leak/add
	19)	 享道出行XDSRC: https://src.saicmobility.com/home/vul/commit/
	20)	 vivoSRC: https://security.vivo.com.cn/#/bugsubmit
	21)	 华为PSIRT: https://bugbounty.huawei.com/
	22)	 火币安全应急响应中心: https://security.huobi.cn
	23)	 马蜂窝安全应急响应中心: https://security.mafengwo.cn/submit
	24)	 喜马拉雅SRC: https://security.ximalaya.com/
	25)	 老虎证券安全应急响应中心: https://security.itiger.com/
	26)	 贝壳安全应急响应中心: https://security.ke.com/vuls
	27)	 金山办公安全应急响应中心: https://security.qwps.cn/report/add
	28)	 度小满安全应急响应中心: https://security.duxiaoman.com/views/main/loophole.html#home
	29)	 水滴安全应急响应中心: https://security.shuidihuzhu.com/bug
	30)	 讯飞安全响应中心: https://security.iflytek.com/user.php/post/add
	31)	 小赢安全应急响应中心: https://security.xiaoying.com/user.php?m=user&amp;c=post&amp;a=add
	32)	 有赞安全应急响应中心: https://src.youzan.com/: https://security.unionpay.com/
	33)	 合合信息安全应急响应中心: https://security.intsig.com
	34)	 BOSS直聘安全应急响应中心: https://src.zhipin.com/report/add
	35)	 火线安全平台: https://www.huoxian.cn/login
	36)	 上汽安吉安全应急响应中心: http://security.anji-plus.com/
	37)	 BIGO Security Response Center: https://security.bigo.sg/#/submittingReport
	38)	 自如安全应急响应中心: https://zrsecurity.ziroom.com
	39)	 敦煌网安全应急响应中心: http://dhsrc.dhgate.com/user.php/login/index/callback/post-add.html
	40)	 货拉拉安全应急响应中心: https://llsrc.huolala.cn/
	41)	 bilibili: https://security.bilibili.com/
	42)	 360SRC: https://security.360.cn/Report/index
	43)	 斗鱼SRC: https://security.douyu.com/
	44)	 苏宁SRC: https://security.suning.com
	45)	 陌陌SRC: https://security.immomo.com
	46)	 百度SRC: http://sec.baidu.com/views/main/loophole.html#home
	47)	 滴滴DSRC: http://sec.didichuxing.com/
	48)	 本地生活SRC: https://security.ele.me/
	49)	 京东SRC: http://security.jd.com/
	50)	 联想SRC: https://lsrc.vulbox.com/
	51)	 同程SRC: https://sec.ly.com/
	52)	 蚂蚁金服SRC: https://security.alipay.com/sc/afsrc/home.htm
	53)	 阿里安全应急响应中心: https://security.alibaba.com/
	54)	 腾讯SRC: https://security.tencent.com/index.php/report/add
	55)	 爱奇艺SRC: https://security.iqiyi.com/#submit
	56)	 补天: http://www.butian.net/Loo/submit
	57)	 唯品会SRC: https://sec.vip.com/
	58)	 网易SRC: http://anquan.163.com/module/hole/new-hole.html
	59)	 途牛SRC: http://sec.tuniu.com/
	60)	 猪八戒SRC: https://sec.zbj.com/
	61)	 点融SRC: https://security.dianrong.com/
	62)	 挖财SRC: https://sec.wacai.com/
	63)	 竞技世界SRC: https://security.jj.cn/
	64)	 富友SRC: https://fsrc.fuiou.com/home/index.html
	65)	 新浪SRC: http://sec.sina.com.cn/
	66)	 携程SRC: https://sec.ctrip.com/report
	67)	 Wifi万能钥匙SRC: https://sec.wifi.com/
	68)	 MLSRC: http://security.mogujie.com/#/
	69)	 美团安全应急响应中心: https://security.meituan.com/
	70)	 好未来安全应急响应中心: http://src.100tal.com/
	71)	 微博安全应急响应中心: http://wsrc.weibo.com/leak_module_view
	72)	 菜鸟安全应急响应中心: http://t.cn/RTT5Pdb
	73)	 小米安全中心: https://sec.xiaomi.com/submit
	74)	 搜狗安全应急响应中心: http://t.cn/RTTVp7I
	75)	 中通安全应急响应中心: https://sec.zto.com/
	76)	 乐信安全应急响应中心: http://security.lexinfintech.com/security/report
	77)	 Seebug漏洞平台: https://www.seebug.org/
	78)	 VIPKID安全应急响应中心: http://t.cn/RTTV3fU
	79)	 你我贷安全应急响应中心: http://www.niwodai.com/index.do?method=login&amp;type=src
	80)	 焦点安全应急响应中心: https://security.focuschina.com/home/index/report.html
	81)	 金山SRC: http://sec.kingsoft.com/hole/submit/
	82)	 平安安全应急响应中心: http://security.pingan.com/submit
	83)	 完美世界SRC: http://security.wanmei.com
	84)	 魅族SRC: https://sec.meizu.com/
	85)	T3出行:https://security.t3go.cn/   t3src@t3go.cn
