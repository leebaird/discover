#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

LLM_ROOT=/opt/llm

repos=(
    "ai-scanner|https://github.com/0din-ai/ai-scanner"
    "basilisk|https://github.com/regaan/basilisk"
    "garak|https://github.com/NVIDIA/garak"
    "giskard-oss|https://github.com/Giskard-AI/giskard-oss"
    "heretic|https://github.com/p-e-w/heretic"
    "jailbreaks|https://github.com/togg53192-cmd/jailbreaks"
    "nuguard|https://github.com/NuGuardAI/nuguard"
    "OBLITERATUS|https://github.com/elder-plinius/OBLITERATUS"
    "promptfoo|https://github.com/promptfoo/promptfoo"
    "PyRIT|https://github.com/microsoft/PyRIT"
)

echo

if ! command -v git &> /dev/null; then
    echo -e "${YELLOW}git is not installed.${NC}"
    exit 1
fi

if [ ! -d "$LLM_ROOT" ]; then
    echo -e "${YELLOW}Creating /opt/llm.${NC}"

    if ! mkdir -p "$LLM_ROOT"; then
        echo -e "${YELLOW}Could not create /opt/llm.${NC}"
        exit 1
    fi

    echo
fi

if [ ! -w "$LLM_ROOT" ]; then
    echo -e "${YELLOW}Could not write /opt/llm. Run with sudo.${NC}"
    exit 1
fi

cd "$LLM_ROOT" || exit

for spec in "${repos[@]}"; do
    name=${spec%%|*}
    url=${spec#*|}

    if [ -d "$name/.git" ]; then
        echo -e "${BLUE}Updating ${name}.${NC}"
        pull_out=$(git -C "$name" pull --ff-only 2>&1) || true

        if echo "$pull_out" | grep -qi 'already up to date'; then
            echo "Already up to date."
        elif echo "$pull_out" | grep -qiE '^(fatal|error):'; then
            printf '%s\n' "$pull_out"
        else
            echo "Updated."
        fi
    elif [ -e "$name" ]; then
        echo -e "${YELLOW}${LLM_ROOT}/${name} exists and is not a git clone. Skipping ${name}.${NC}"
    else
        echo -e "${YELLOW}Installing ${name}.${NC}"
        if ! git clone "$url" "$name"; then
            echo -e "${YELLOW}Could not clone ${name}.${NC}"
        fi
    fi

    echo
done

