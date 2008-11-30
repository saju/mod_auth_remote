#
# make sure the correct apxs in your path first - or modify this file to pickup the correct apxs
#
APXS=apxs

all:
	$(APXS) -Wc,-Wall -i -a -c -n auth_remote -l crypto -l ssl mod_auth_remote.c ssl.c plain.c

#
# if your apr lib does not have apr_random_* apis
# or if you lack a good source of randomness (truerand)
# use this target. this will remove the dependency on the random apis
# but will also disable support for cookies
#
no_random:
	$(APXS) -D AUTH_REMOTE_NO_SALT -i -a -c mod_auth_remote.c