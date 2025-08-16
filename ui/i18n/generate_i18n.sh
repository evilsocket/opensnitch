#!/bin/sh

app_name="opensnitch"
langs_dir="./locales"
lrelease_bin=""
for lbin in $LRELEASE lrelease lrelease6 lrelease-qt6
do
    lrelease_bin="$(command -v $lbin)"
    if [ -n "$lrelease_bin" ]; then
        break
    fi
done
if [ -z "$lrelease_bin" ]; then
    echo "lrelease binary not found!"
    exit 1
fi
echo "using $lrelease_bin"

#pylupdate5 opensnitch_i18n.pro

for lang in $(ls $langs_dir)
do
    lang_path="$langs_dir/$lang/$app_name-$lang"
    $lrelease_bin $lang_path.ts -qm $lang_path.qm
done
