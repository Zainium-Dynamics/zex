#compdef zex
# zex zsh completion
# Install: copy to a directory in your $fpath

_zex() {
    local state

    _arguments \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            local commands
            commands=(
                'install:Install packages'
                'remove:Remove installed packages'
                'update:Full system update'
                'uland:Upgrade userland packages'
                'syshub:Upgrade immutable syshub base'
                'search:Search repositories'
                'doctor:Audit and repair system'
                'rollback:Revert a transaction'
                'sweep:Clean cache and temp files'
                'inspect:Deep-inspect a package'
                'depends:Show dependency tree'
                'why:Show reverse dependencies'
                'pin:Lock package version'
                'unpin:Release version lock'
                'pins:List pinned packages'
            )
            _describe 'command' commands
            ;;
        args)
            case $words[2] in
                install)
                    _arguments '--dry-resolve[Preview only]' '--cache-only[Offline mode]'
                    ;;
                remove|pin|unpin|inspect|depends|why)
                    local pkgs
                    pkgs=(${(f)"$(ls /overlayer/zexlib/registry/installed/*.toml 2>/dev/null \
                                 | xargs -I{} basename {} .toml 2>/dev/null)"})
                    _values 'installed package' $pkgs
                    ;;
                sweep)
                    _arguments '--dry-run[Preview only]' '--aggressive[Also clean logs]' '-y[Skip prompt]'
                    ;;
                doctor)
                    _arguments '--fix[Auto-repair issues]'
                    ;;
                update)
                    _arguments '--yes[No prompt]' '--uland-only[Userland only]' '--syshub-only[Syshub only]'
                    ;;
                search)
                    _arguments '--tier[Tier number]:tier:(1 2 3 4)' '--installed[Installed only]'
                    ;;
            esac
            ;;
    esac
}

_zex
