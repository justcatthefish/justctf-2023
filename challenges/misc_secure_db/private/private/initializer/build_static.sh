#!/usr/bin/env sh

rm -f ../solver/cloud.key
rm -f ../solver/db
rm -f ../db
rm -f ../private.key
rm -f ../../public/data -r
rm -f ../../public/test_data -r


docker build -t initializer-misc-secure_db .
docker run --rm -it \
    --network=host \
    -v `pwd`:/result \
    --workdir /result \
    initializer-misc-secure_db \
    /tool/initializer

mkdir ../../public/data

cp cloud.key ../../public/data/cloud.key
mv cloud.key ../solver/cloud.key
mv private.key ../private.key

cp db ../db
cp db ../../public/data/db
mv db ../solver/db

# test data

docker run --rm -it \
    --network=host \
    -v `pwd`:/result \
    --workdir /result \
    initializer-misc-secure_db \
    /tool/initializer

mkdir ../../public/test_data

mv cloud.key ../../public/test_data/cloud.key
mv private.key ../../public/test_data/private.key
mv db ../../public/test_data/db
