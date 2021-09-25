# https://51pwn.com

## get country ip lists for nmap

```
wget https://www.nirsoft.net/countryip/index.html

cat index.html|grep -Eo '<td><a href="([^"]+)"'|sed -E 's/<td><a href="|"|\.html//g'|sort -u|uniq|xargs -I % bash -c 'echo %.csv;wget -O %.csv -c https://www.nirsoft.net/countryip/%.csv'

rm index.html

```
