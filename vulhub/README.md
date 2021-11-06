
# Quickly build target docker resources

```
curl -s -q -k -o-  'https://hub.docker.com/u/vulfocus?page=1&page_size=2500' |  grep -Eo  '(vulfocus\/[^<]+)'> vulfocus.txt
cat vulfocus.txt|  grep -Eo  '(vulfocus\/[^"<]+)'|sort -u -b|uniq |xargs -I % docker pull %


git clone https://github.com/vulhub/vulhub.git  $HOME/MyWork/vulhub
find  $HOME/MyWork/vulhub -name "docker-compose.yml"|xargs -I % cat %|grep "image:"|sed  -E 's/\s*image://g'|sort -u|grep vulhub > vulhub.txt
# find $HOME/MyWork/vulhub -name "docker-compose.yml"|xargs -I % cat %|grep "image:"|sed  -E 's/\s*image://g'|sort -u|grep vulhub
cat vulhub.txt|xargs -I K docker pull K



curl -s -q -k -o-  'https://hub.docker.com/v2/repositories/medicean/vulapps/tags/?page_size=250&page=1' |  grep -Eo  '"name":"[^"]+'|sed -E 's/"name":"/medicean\/vulapps:/g'>vulapps.txt
cat vulapps.txt|grep  vulapps |xargs -I % docker pull %

git clone https://github.com/c0ny1/vulstudy $HOME/MyWork/
cd $HOME/MyWork/vulstudy
docker-compose up -d
docker-compose stop

# OWASP Juice Shop: Probably the most modern and sophisticated insecure web application
# https://github.com/juice-shop/juice-shop
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop

```
