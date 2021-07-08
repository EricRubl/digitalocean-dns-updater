"""
    Uncomment lines before merge to confirm behavior is as expected.
"""

#!/usr/bin/env bash


for i in "$@"
do
case $i in
    --venv=*)
    PREFIX="${i#*=}"

    ;;

esac
done

if [ "$PREFIX" = "" ]
then
        echo ""
else
        python3 -m virtualenv $PREFIX
        ls | grep -v $PREFIX | xargs mv -t $PREFIX
        cd $PREFIX
        source bin/activate
        python3 -m pip install -r requirements.txt


        #mkdir /etc/digitalocean-dns-updater
        #cp config.yml /etc/digitalocean-dns-updater
        #cp *.py /etc/digitalocean-dns-updater

        # ETC lines not changed! assuming ./lib is used
        # - p0licat
        #cp dodnsupdater.service ./lib/systemd/system
        #chmod 644 ./lib/systemd/system/dodnsupdater.service

        #systemctl daemon-reload
        #systemctl enable dodnsupdater.service
fi

#mkdir /etc/digitalocean-dns-updater
#cp config.yml /etc/digitalocean-dns-updater
#cp *.py /etc/digitalocean-dns-updater
#cp dodnsupdater.service /lib/systemd/system
#chmod 644 /lib/systemd/system/dodnsupdater.service
#systemctl daemon-reload
#systemctl enable dodnsupdater.service
