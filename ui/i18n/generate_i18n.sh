#!/bin/sh

app_name="opensnitch"
langs_dir="./locales"
lrelease="lrelease"
if ! command -v lrelease >/dev/null; then
    # on fedora
    lrelease="lrelease-qt5"
fi

#pylupdate5 opensnitch_i18n.pro

for lang in $(ls $langs_dir)
do
    lang_path="$langs_dir/$lang/$app_name-$lang"
    $lrelease $lang_path.ts -qm $lang_path.qm
done
