# zex bash completion
# Install: source this file in ~/.bashrc or
#   copy to /overlayer/syshub/share/bash-completion/completions/zex

_zex_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="install remove update upgrade uland syshub search
                    doctor rollback sweep inspect depends why pin unpin pins"

    case $cword in
        1)
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            ;;
        *)
            case "${words[1]}" in
                install)
                    COMPREPLY=($(compgen -W "--dry-resolve --cache-only" -- "$cur"))
                    ;;
                remove)
                    if compgen -G "/overlayer/zexlib/registry/installed/*.toml" &>/dev/null; then
                        local pkgs
                        pkgs=$(ls /overlayer/zexlib/registry/installed/*.toml 2>/dev/null \
                               | xargs -I{} basename {} .toml)
                        COMPREPLY=($(compgen -W "$pkgs" -- "$cur"))
                    fi
                    ;;
                pin|unpin|inspect|depends|why)
                    if compgen -G "/overlayer/zexlib/registry/installed/*.toml" &>/dev/null; then
                        local pkgs
                        pkgs=$(ls /overlayer/zexlib/registry/installed/*.toml 2>/dev/null \
                               | xargs -I{} basename {} .toml)
                        COMPREPLY=($(compgen -W "$pkgs" -- "$cur"))
                    fi
                    ;;
                sweep)
                    COMPREPLY=($(compgen -W "--dry-run --aggressive --yes" -- "$cur"))
                    ;;
                doctor)
                    COMPREPLY=($(compgen -W "--fix" -- "$cur"))
                    ;;
                update)
                    COMPREPLY=($(compgen -W "--yes --uland-only --syshub-only" -- "$cur"))
                    ;;
                search)
                    COMPREPLY=($(compgen -W "--tier --installed" -- "$cur"))
                    ;;
            esac
            ;;
    esac
}

complete -F _zex_completions zex
