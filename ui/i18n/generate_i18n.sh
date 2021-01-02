#!/bin/sh

app_name="opensnitch"
langs_dir="./locales"

#pylupdate5 opensnitch_i18n.pro

for lang in $(ls $langs_dir)
do
    lang_path="$langs_dir/$lang/$app_name-$lang"
    lrelease $lang_path.ts -qm $lang_path.qm
done
