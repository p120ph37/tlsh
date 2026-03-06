#!/usr/bin/env bash
# jit.sh - Generalized JIT function inliner for subshell elimination
#
# Rewrites function bodies by copying the source of "inlinable" callees
# directly into the caller, eliminating subshell forks. Functions are
# registered as inlinable via _jit_mark_inlinable. The JIT inspects each
# callee's source (via declare -f), substitutes positional parameters,
# namespaces local variables, and transforms the return (stdout printf)
# into a variable assignment.
#
# Usage:
#   _jit_mark_inlinable func1 func2 ...  # Register inlinable functions
#   _jit_inline target_func              # Rewrite target_func in place
#
# Inlinable function contract:
#   - Returns output via a single printf at the end of the body
#   - Either a one-liner: printf 'FMT' EXPR
#   - Or accumulate-and-return: build local var, then printf '%s' "$var"
#   - Positional params ($1, $2) used only for input
#   - No side effects (no global variable writes, no I/O beyond return)

# --- Registry ---

# Space-delimited list of inlinable function names
_jit_registry=" "

# _jit_mark_inlinable <func...> - Register functions as inlinable
_jit_mark_inlinable() {
    local fn
    for fn in "$@"; do
        _jit_registry="${_jit_registry}${fn} "
    done
}

# _jit_is_inlinable <funcname> - Check if function is registered
_jit_is_inlinable() {
    case "$_jit_registry" in
        *" $1 "*) return 0 ;;
        *)        return 1 ;;
    esac
}

# --- Unique name generation ---
_jit_uid=0

# Increment _jit_uid and store result in _jit_cur_uid (no subshell)
_jit_next_uid() {
    _jit_uid=$((_jit_uid + 1))
    _jit_cur_uid=$_jit_uid
}

# --- Function body extraction ---

# _jit_get_body <funcname>
# Extracts the body of a function from declare -f output.
# Each line is separated by newlines, preserving indentation.
# Result is stored in _jit_body.
_jit_get_body() {
    local func_name="$1"
    local src
    src=$(declare -f "$func_name") || return 1
    _jit_body=""
    local in_body=0
    local line
    while IFS= read -r line; do
        local trimmed="${line%"${line##*[![:space:]]}"}"
        [ -z "$trimmed" ] && trimmed="$line"
        if [ $in_body -eq 0 ]; then
            case "$trimmed" in
                *"()"*|*"()") continue ;;
                "{"*) in_body=1; continue ;;
            esac
            continue
        fi
        [ "$trimmed" = "}" ] && continue
        _jit_body="${_jit_body}${line}
"
    done <<< "$src"
}

# --- Argument parsing from call site ---

# _jit_parse_args <args_string>
# Parse space-separated arguments, respecting double quotes.
# Sets _jit_argv array and _jit_argc count.
_jit_argc=0

_jit_parse_args() {
    local input="$1"
    _jit_argc=0
    # Reset argv
    local idx=0
    local remaining="$input"

    while [ -n "$remaining" ]; do
        # Skip leading spaces
        remaining="${remaining#"${remaining%%[![:space:]]*}"}"
        [ -z "$remaining" ] && break

        local arg=""
        case "$remaining" in
            '"'*)
                # Quoted argument: find closing quote
                remaining="${remaining#\"}"
                arg="${remaining%%\"*}"
                remaining="${remaining#*\"}"
                ;;
            *)
                # Unquoted argument: take until space
                arg="${remaining%% *}"
                if [ "$arg" = "$remaining" ]; then
                    remaining=""
                else
                    remaining="${remaining#* }"
                fi
                ;;
        esac
        eval "_jit_argv_${idx}=\"\${arg}\""
        idx=$((idx + 1))
    done
    _jit_argc=$idx
}

# _jit_get_arg <index> - Get parsed argument by 0-based index
_jit_get_arg() {
    eval "printf '%s' \"\$_jit_argv_$1\""
}

# --- Body transformation ---

# _jit_collect_locals <body>
# Collect local variable names from function body.
# Sets _jit_locals as space-separated list, longest first.
_jit_collect_locals() {
    local body="$1"
    local names=""
    local line

    while IFS= read -r line; do
        local stripped="${line#"${line%%[![:space:]]*}"}"
        # Strip trailing semicolon
        stripped="${stripped%%;}"
        case "$stripped" in
            "local "*)
                local decl="${stripped#local }"
                # May be "local var" or "local var=..." or "local var1 var2"
                # Handle var=... by taking just the name part
                local word
                for word in $decl; do
                    local vname="${word%%=*}"
                    # Validate it's an identifier
                    case "$vname" in
                        *[!a-zA-Z0-9_]*) continue ;;
                        "") continue ;;
                    esac
                    # Add to list if not already present
                    case " $names " in
                        *" $vname "*) ;;
                        *) names="${names}${vname} " ;;
                    esac
                done
                ;;
        esac
    done <<< "$body"

    # Sort by length descending (longest first to avoid substring issues)
    # Simple insertion sort since we have few names
    _jit_locals=""
    while [ -n "$names" ]; do
        local longest="" longest_len=0
        for word in $names; do
            if [ ${#word} -gt $longest_len ]; then
                longest="$word"
                longest_len=${#word}
            fi
        done
        _jit_locals="${_jit_locals}${longest} "
        # Remove it from names
        names="${names//${longest} /}"
    done
}

# _jit_rename_locals <body> <prefix>
# Rename all local variables in body with given prefix.
# Handles: $var, ${var}, ${var:...}, ${#var}, and local declarations.
# Returns result in _jit_renamed.
_jit_rename_locals() {
    local body="$1"
    local pfx="$2"

    _jit_collect_locals "$body"

    local name
    for name in $_jit_locals; do
        # Order matters: most specific patterns first

        # ${#name} → ${#pfx_name}
        body="${body//\$\{#${name}\}/\$\{#${pfx}${name}\}}"
        body="${body//\$\{#${name}\}/\$\{#${pfx}${name}\}}"

        # ${name: → ${pfx_name: (substring expressions)
        body="${body//\$\{${name}:/\$\{${pfx}${name}:}"

        # ${name%% → ${pfx_name%%  (parameter expansion operators)
        body="${body//\$\{${name}%%/\$\{${pfx}${name}%%}"
        body="${body//\$\{${name}%/\$\{${pfx}${name}%}"
        body="${body//\$\{${name}##/\$\{${pfx}${name}##}"
        body="${body//\$\{${name}#/\$\{${pfx}${name}#}"
        body="${body//\$\{${name}\/\//\$\{${pfx}${name}\/\/}"

        # ${name} → ${pfx_name}
        body="${body//\$\{${name}\}/\$\{${pfx}${name}\}}"

        # "local name" declarations (with = or without)
        body="${body//local ${name}=/local ${pfx}${name}=}"
        body="${body//local ${name};/local ${pfx}${name};}"
        body="${body//local ${name} /local ${pfx}${name} }"

        # "printf -v name" → "printf -v pfx_name" (printf-to-variable)
        body="${body//printf -v ${name} /printf -v ${pfx}${name} }"

        # Bare assignment: name= → pfx_name= (not preceded by $, {, or _)
        # Handle start-of-line and after-whitespace assignments
        local _line _newbody=""
        while IFS= read -r _line; do
            local _s="${_line#"${_line%%[![:space:]]*}"}"
            local _ind="${_line%%[![:space:]]*}"
            case "$_s" in
                "${name}="*|"${pfx}${name}="*)
                    # Already prefixed or needs prefixing
                    case "$_s" in
                        "${pfx}${name}="*) ;;  # already done
                        "${name}="*) _line="${_ind}${pfx}${_s}" ;;
                    esac
                    ;;
            esac
            _newbody="${_newbody}${_line}
"
        done <<< "$body"
        body="$_newbody"

        # $name → $pfx_name (remaining bare references)
        # We do this last and rely on longest-first ordering
        body="${body//\$${name}/\$${pfx}${name}}"

        # Bare name in arithmetic: $((name → $((_pfx_name
        body="${body//(( ${name} /(( ${pfx}${name} }"
        body="${body//(( ${name}+/(( ${pfx}${name}+}"
        body="${body//(( ${name}-/(( ${pfx}${name}-}"
        body="${body//(( ${name})/(( ${pfx}${name})}"
        body="${body//((${name} /((${pfx}${name} }"
        body="${body//((${name}+/((${pfx}${name}+}"
        body="${body//((${name}-/((${pfx}${name}-}"
        body="${body//((${name})/((${pfx}${name})}"
    done

    _jit_renamed="$body"
}

# _jit_sub_positional <body> <arg1> <arg2> ...
# Replace $1, $2, etc. with actual argument values.
# Process in reverse order to avoid $1 matching inside $10.
# Result stored in _jit_subbed.
_jit_sub_positional() {
    local body="$1"
    shift
    local nargs=$#

    # Replace in reverse order ($9 before $1)
    local n=$nargs
    while [ $n -ge 1 ]; do
        local arg="${!n}"
        # ${N} form
        body="${body//\$\{${n}\}/${arg}}"
        # $N form (only safe for single digits when done in reverse)
        body="${body//\$${n}/${arg}}"
        n=$((n - 1))
    done

    _jit_subbed="$body"
}

# _jit_transform_return <body> <result_var>
# Find the return mechanism (final printf) and transform it to a variable
# assignment. Handles two patterns:
#   1. Single-line: printf 'FMT' EXPR → printf -v result_var 'FMT' EXPR
#   2. Accumulate:  printf '%s' "$var" → result_var="$var"
# Returns result in _jit_transformed. Also sets _jit_return_lines with
# the number of trailing lines consumed by the return.
_jit_transform_return() {
    local body="$1"
    local result_var="$2"

    # Split body into lines, find the last printf
    local lines=""
    local line_count=0
    local last_printf_line=""
    local last_printf_num=0
    local line

    while IFS= read -r line; do
        line_count=$((line_count + 1))
        lines="${lines}${line}
"
        local stripped="${line#"${line%%[![:space:]]*}"}"
        stripped="${stripped%%;}"
        case "$stripped" in
            "printf "*)
                last_printf_line="$line"
                last_printf_num=$line_count
                ;;
        esac
    done <<< "$body"

    if [ $last_printf_num -eq 0 ]; then
        # No printf found — function has no return value, just copy body
        _jit_transformed="$body"
        return 1
    fi

    # Parse the printf: is it printf '%s' "$var" or printf 'FMT' EXPR?
    local stripped="${last_printf_line#"${last_printf_line%%[![:space:]]*}"}"
    stripped="${stripped%%;}"
    local indent="${last_printf_line%%[![:space:]]*}"

    # Remove "printf " prefix
    local printf_args="${stripped#printf }"
    # Remove possible quotes around format string
    local fmt_char="${printf_args:0:1}"
    local fmt="" rest_args=""
    case "$fmt_char" in
        "'"*)
            printf_args="${printf_args#\'}"
            fmt="${printf_args%%\'*}"
            rest_args="${printf_args#*\'}"
            rest_args="${rest_args# }"
            ;;
        '"'*)
            printf_args="${printf_args#\"}"
            fmt="${printf_args%%\"*}"
            rest_args="${printf_args#*\"}"
            rest_args="${rest_args# }"
            ;;
        *)
            fmt="${printf_args%% *}"
            rest_args="${printf_args#* }"
            ;;
    esac

    # Reconstruct body with transformed return
    _jit_transformed=""
    local cur=0
    while IFS= read -r line; do
        cur=$((cur + 1))
        if [ $cur -eq $last_printf_num ]; then
            if [ "$fmt" = "%s" ]; then
                # Accumulate pattern: printf '%s' "$var" → result_var=$var
                # Strip quotes from the variable reference
                local var_ref="${rest_args//\"/}"
                _jit_transformed="${_jit_transformed}${indent}${result_var}=\"${var_ref}\"
"
            else
                # Format pattern: printf 'FMT' EXPR → printf -v result_var 'FMT' EXPR
                _jit_transformed="${_jit_transformed}${indent}printf -v ${result_var} '${fmt}' ${rest_args}
"
            fi
        else
            _jit_transformed="${_jit_transformed}${line}
"
        fi
    done <<< "$body"
}

# --- Core inlining engine ---

# _jit_expand_call <callee_name> <args_string> <result_var> <indent>
# Generate the inlined body for a single call site.
# Result stored in _jit_expansion.
_jit_expand_call() {
    local callee="$1"
    local args_str="$2"
    local result_var="$3"
    local indent="$4"

    # Get callee body
    _jit_get_body "$callee" || return 1
    local body="$_jit_body"

    # Parse arguments
    _jit_parse_args "$args_str"
    local actual_args=()
    local ai=0
    while [ $ai -lt $_jit_argc ]; do
        actual_args+=("$(_jit_get_arg $ai)")
        ai=$((ai + 1))
    done

    # Generate unique prefix for local variable namespacing
    _jit_next_uid
    local pfx="_il${_jit_cur_uid}_"

    # IMPORTANT: Rename locals BEFORE substituting positional parameters.
    # Otherwise $1→$caller_var gets mistakenly renamed as a callee local.
    _jit_rename_locals "$body" "$pfx"
    body="$_jit_renamed"

    # Now substitute positional parameters ($1, $2, etc.) with actual args
    _jit_sub_positional "$body" "${actual_args[@]}"
    body="$_jit_subbed"

    # Transform return printf into variable assignment
    _jit_transform_return "$body" "$result_var"
    body="$_jit_transformed"

    # Re-indent all lines to match call site
    _jit_expansion=""
    local line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Strip original 4-space indent from declare -f, add call-site indent
        local stripped="${line#    }"
        _jit_expansion="${_jit_expansion}${indent}${stripped}
"
    done <<< "$body"
}

# --- Main entry points ---

# _jit_inline <func_name...> - Rewrite functions with inlinable calls expanded
_jit_inline() {
    local func_name
    for func_name in "$@"; do
        _jit_inline_one "$func_name" 0
    done
}

# _jit_inline_one <func_name> <depth>
# Rewrite a single function. Recurses up to depth 3 for nested inlinable calls.
_jit_inline_one() {
    local func_name="$1"
    local depth="${2:-0}"

    [ "$depth" -gt 3 ] && return 0  # prevent infinite recursion

    # Get function source
    _jit_get_body "$func_name" || {
        printf 'jit: function %s not found\n' "$func_name" >&2
        return 1
    }
    local orig_body="$_jit_body"

    # Check if body contains any inlinable calls
    local has_inlinable=0
    local fn
    for fn in $_jit_registry; do
        [ -z "$fn" ] && continue
        case "$orig_body" in
            *'$('${fn}' '*)
                has_inlinable=1
                break
                ;;
        esac
    done

    # Also check for $(printf 'fmt' ...) which can be converted to printf -v
    case "$orig_body" in
        *'$(printf '*) has_inlinable=1 ;;
    esac

    [ $has_inlinable -eq 0 ] && return 0

    # Process line by line
    local new_body=""
    local line
    while IFS= read -r line; do
        local stripped="${line#"${line%%[![:space:]]*}"}"
        local indent="${line%%[![:space:]]*}"
        stripped="${stripped%%;}"  # strip trailing semicolon

        local did_inline=0

        # --- Direct assignment: [local] var=$(func args) ---
        local has_local=0
        local check="$stripped"
        case "$check" in
            "local "*)
                has_local=1
                check="${check#local }"
                check="${check#"${check%%[![:space:]]*}"}"
                ;;
        esac

        case "$check" in
            *'=$('*')'|*'="$('*')"')
                local varname="${check%%=*}"
                case "$varname" in
                    *[!a-zA-Z0-9_]*) ;;  # not simple identifier
                    *)
                        local rhs="${check#*=}"
                        # Strip optional quotes
                        case "$rhs" in '"$('*')"') rhs="${rhs#\"}"; rhs="${rhs%\"}";; esac

                        # Verify single subshell
                        local rhs_rest="${rhs#*\$(}"
                        case "$rhs_rest" in
                            *'$('*) ;;  # multiple subshells, skip
                            *)
                                case "$rhs" in
                                    '$('*')')
                                        local inner="${rhs#\$(}"
                                        inner="${inner%)}"
                                        local callee="${inner%% *}"
                                        local callee_args="${inner#* }"
                                        [ "$callee_args" = "$inner" ] && callee_args=""

                                        if _jit_is_inlinable "$callee"; then
                                            # Full function body inlining
                                            # Strip quotes for function arg parsing
                                            callee_args="${callee_args//\"/}"
                                            if [ $has_local -eq 1 ]; then
                                                new_body="${new_body}${indent}local ${varname}
"
                                            fi
                                            _jit_expand_call "$callee" "$callee_args" "$varname" "$indent"
                                            new_body="${new_body}${_jit_expansion}"
                                            did_inline=1
                                        elif [ "$callee" = "printf" ]; then
                                            # $(printf 'fmt' expr) → printf -v var 'fmt' expr
                                            # Preserve original quoting for printf args
                                            if [ $has_local -eq 1 ]; then
                                                new_body="${new_body}${indent}local ${varname}; printf -v ${varname} ${callee_args}
"
                                            else
                                                new_body="${new_body}${indent}printf -v ${varname} ${callee_args}
"
                                            fi
                                            did_inline=1
                                        fi
                                        ;;
                                esac
                                ;;
                        esac
                        ;;
                esac
                ;;
        esac

        # --- Inline within string concatenation: "...$(func args)..." ---
        if [ $did_inline -eq 0 ]; then
            local remaining="$line"
            local rebuilt=""
            local preamble=""
            local found_any=0

            while true; do
                # Find earliest inlinable $(func call
                local best_pos=999999 best_fn="" best_pre="" best_aft=""

                for fn in $_jit_registry; do
                    [ -z "$fn" ] && continue
                    case "$remaining" in
                        *'$('${fn}' '*)
                            local pre="${remaining%%\$\(${fn} *}"
                            if [ ${#pre} -lt $best_pos ]; then
                                best_pos=${#pre}
                                best_fn="$fn"
                                best_pre="$pre"
                                best_aft="${remaining#*\$\(${fn} }"
                            fi
                            ;;
                    esac
                done

                # Also check for $(printf
                case "$remaining" in
                    *'$(printf '*)
                        local pre="${remaining%%\$(printf *}"
                        if [ ${#pre} -lt $best_pos ]; then
                            best_pos=${#pre}
                            best_fn="printf"
                            best_pre="$pre"
                            best_aft="${remaining#*\$(printf }"
                        fi
                        ;;
                esac

                [ $best_pos -eq 999999 ] && break

                found_any=1
                # Find matching close paren, accounting for nested $((...))
                local arg=""
                remaining="$best_aft"
                local _pdepth=1
                while [ $_pdepth -gt 0 ] && [ -n "$remaining" ]; do
                    local _ch="${remaining:0:1}"
                    remaining="${remaining:1}"
                    case "$_ch" in
                        "(")
                            _pdepth=$((_pdepth + 1))
                            arg="${arg}("
                            ;;
                        ")")
                            _pdepth=$((_pdepth - 1))
                            [ $_pdepth -gt 0 ] && arg="${arg})"
                            ;;
                        *)
                            arg="${arg}${_ch}"
                            ;;
                    esac
                done

                _jit_next_uid
                local tmpvar="_jv${_jit_cur_uid}"

                if [ "$best_fn" = "printf" ]; then
                    # $(printf 'fmt' expr) → printf -v tmpvar 'fmt' expr
                    # Preserve original quoting for printf args
                    preamble="${preamble}${indent}printf -v ${tmpvar} ${arg}
"
                else
                    # Full function body inlining into temp var
                    # Strip quotes from function call args
                    arg="${arg//\"/}"
                    _jit_expand_call "$best_fn" "$arg" "$tmpvar" "$indent"
                    preamble="${preamble}${_jit_expansion}"
                fi
                rebuilt="${rebuilt}${best_pre}\${${tmpvar}}"
            done

            if [ $found_any -eq 1 ]; then
                rebuilt="${rebuilt}${remaining}"
                new_body="${new_body}${preamble}${rebuilt}
"
                did_inline=1
            fi
        fi

        # --- Passthrough: no inlining needed ---
        if [ $did_inline -eq 0 ]; then
            new_body="${new_body}${line}
"
        fi

    done <<< "$orig_body"

    # Reconstruct and eval the function
    # Note: "${new_body}" does NOT recursively expand $ references inside
    # the value of new_body. Eval then parses the function definition, which
    # stores the body for runtime expansion.
    local header="${func_name} ()"
    eval "${header} {
${new_body}}"

    # Recursive pass: the inlined body might contain more inlinable calls
    _jit_inline_one "$func_name" $((depth + 1))
}
