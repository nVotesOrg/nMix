#!/bin/sh
# http://planzero.org/blog/2012/10/24/hosting_an_admin-friendly_git_server_with_git-shell
rm -r -f /srv/data/git/repo.git
mkdir /srv/data/git/repo.git
git --bare init /srv/data/git/repo.git
rm -r -f repo
git clone /srv/data/git/repo.git
cp config.json repo
cp config.stmt.json repo
cd repo
git add .
git commit -a -m "first commit"
git push origin master
chown -R git.git /srv/data/git/repo.git
cd ..
rm -r -f datastore
rm -r -f datastore2
rm -r -f datastore3
mkdir datastore
mkdir datastore2
mkdir datastore3