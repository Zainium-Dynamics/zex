# zex fish completion
# Install: copy to ~/.config/fish/completions/zex.fish or
#   /overlayer/syshub/share/fish/vendor_completions.d/zex.fish

function __zex_installed_packages
    ls /overlayer/zexlib/registry/installed/*.toml 2>/dev/null | xargs -I{} basename {} .toml 2>/dev/null
end

set -l zex_commands install remove update uland syshub search doctor rollback sweep inspect depends why pin unpin pins

# Top-level commands
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a install    -d "Install packages"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a remove     -d "Remove packages"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a update     -d "Full system update"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a uland      -d "Upgrade userland"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a syshub     -d "Upgrade syshub base"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a search     -d "Search repositories"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a doctor     -d "Audit system health"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a rollback   -d "Revert transaction"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a sweep      -d "Clean cache"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a inspect    -d "Inspect package"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a depends    -d "Dependency tree"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a why        -d "Reverse dependencies"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a pin        -d "Pin package version"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a unpin      -d "Release pin"
complete -c zex -f -n "not __fish_seen_subcommand_from $zex_commands" -a pins       -d "List pinned packages"

# install flags
complete -c zex -f -n "__fish_seen_subcommand_from install" -l dry-resolve -d "Preview only"
complete -c zex -f -n "__fish_seen_subcommand_from install" -l cache-only  -d "Offline mode"

# remove / pin / unpin / inspect / depends / why — complete with installed packages
for cmd in remove pin unpin inspect depends why
    complete -c zex -f -n "__fish_seen_subcommand_from $cmd" -a "(__zex_installed_packages)"
end

# sweep flags
complete -c zex -f -n "__fish_seen_subcommand_from sweep" -l dry-run    -d "Preview only"
complete -c zex -f -n "__fish_seen_subcommand_from sweep" -l aggressive -d "Also clean logs"
complete -c zex -f -n "__fish_seen_subcommand_from sweep" -s y          -d "Skip prompt"

# doctor flags
complete -c zex -f -n "__fish_seen_subcommand_from doctor" -l fix -d "Auto-repair"

# update flags
complete -c zex -f -n "__fish_seen_subcommand_from update" -s y           -d "No prompt"
complete -c zex -f -n "__fish_seen_subcommand_from update" -l uland-only  -d "Userland only"
complete -c zex -f -n "__fish_seen_subcommand_from update" -l syshub-only -d "Syshub only"

# search flags
complete -c zex -f -n "__fish_seen_subcommand_from search" -l tier      -d "Tier (1-4)"
complete -c zex -f -n "__fish_seen_subcommand_from search" -l installed -d "Installed only"
