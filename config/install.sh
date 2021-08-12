#!/bin/bash

if [[ $UID == 0 ]]; then
     home='/root/'
else
     home=`(eval echo ~$USER/)`
fi

cp tmux.conf $home.tmux.conf
cp vimrc $home.vimrc
cat zshrc >> $home.zshrc

source $home.zshrc 2>/dev/null
