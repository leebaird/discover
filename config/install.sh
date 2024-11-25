#!/bin/bash

cp tmux.conf "$HOME"/.tmux.conf
cp vimrc "$HOME"/.vimrc
cat zshrc >> "$HOME"/.zshrc

source "$HOME"/.zshrc 2>/dev/null
