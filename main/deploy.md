EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean
idf.py all

EXTRA_CFLAGS=
export EXTRA_CFLAGS
idf.py fullclean
idf.py all

works, but painfull