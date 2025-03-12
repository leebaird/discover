#!/bin/bash

cp tmux.conf "$HOME"/.tmux.conf
cp vimrc "$HOME"/.vimrc

if grep -iq "kali" /etc/os-release; then
    cat zshrc >> "$HOME"/.zshrc
    source "$HOME"/.zshrc 2>/dev/null
else
    cp zshrc "$HOME"/.bash_aliases
    source "$HOME"/.bash_aliases
fi
