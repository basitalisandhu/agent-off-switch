# Records docs/demo.gif with charmbracelet/vhs (https://github.com/charmbracelet/vhs).
#
# Reproduce from the repository root:
#   python -m pip install .
#   vhs docs/demo.tape
#
# The output is the real output of aos on the synthetic tenant in
# examples/demo-tenant, pinned to --as-of 2026-10-09 so it does not change
# with the date. The pipes only shorten it to fit the frame.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 540
Set Padding 20
Set LineHeight 1.25
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Framerate 12
Set PlaybackSpeed 1.0

Hide
Type "export PS1='$ ' && clear"
Enter
Show

Sleep 500ms
Type "aos review examples/demo-tenant --as-of 2026-10-09 | head -n 15"
Sleep 300ms
Enter
Sleep 8s

Type "clear"
Enter
Type "aos off examples/demo-tenant aws-role:coding-agent-runner --as-of 2026-10-09 | grep -E '^(# |Identity|### Step)'"
Sleep 300ms
Enter
Sleep 9s
