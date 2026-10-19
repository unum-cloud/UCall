"""Formatting policy for the CMake source files."""

# Controls the CMakeLists.txt file formatting for the `cmake-format` tool.
# https://cmake-format.readthedocs.io/en/latest/configuration.html

with section("format"):
    line_width = 120
    tab_size = 2

    # If an argument group contains more than this many sub-groups (parg or kwarg
    # groups) then force it to a vertical layout.
    max_subgroups_hwrap = 2

    # If a positional argument group contains more than this many arguments, then
    # force it to a vertical layout.
    max_pargs_hwrap = 6

    # Format command names consistently as 'lower' or 'upper' case
    command_case = "canonical"

    # If true, separate flow control names from their parentheses with a space
    separate_ctrl_name_with_space = True

    # If true, separate function names from parentheses with a space
    separate_fn_name_with_space = True

    # If a statement is wrapped to more than one line, than dangle the closing
    # parenthesis on its own line.
    dangle_parens = True

with section("markup"):
    # What character to use for bulleted lists
    bullet_char = "*"

    # What character to use as punctuation after numerals in an enumerated list
    enum_char = "."
