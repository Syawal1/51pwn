Twitter: [@Hktalent3135773](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773)
[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=myhktools%20-%20Automated%20Pentest%20Recon%20Scanner%20%40Hktalent3135773&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2Fhktalent%2Fmyhktools)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773)
# 51pwn

## get country ip lists for nmap

```
wget https://www.nirsoft.net/countryip/index.html

cat index.html|grep -Eo '<td><a href="([^"]+)"'|sed -E 's/<td><a href="|"|\.html//g'|sort -u|uniq|xargs -I % bash -c 'echo %.csv;wget -O %.csv -c https://www.nirsoft.net/countryip/%.csv'

rm index.html

```
