#!/usr/bin/env bash
# jit.sh - JIT function inliner for subshell elimination
#
# At source time, rewrites function bodies to replace known subshell calls
# like $(uint16_to_hex EXPR) with inline printf -v equivalents that avoid
# fork overhead. The original decomposed source is kept clean; the JIT
# produces optimized versions in memory only.
#
# Usage:
#   _jit_inline funcname           # Rewrite funcname in place
#   _jit_inline funcname funcname2 # Rewrite multiple functions

# Counter for generating unique temp variable names per function rewrite
_jit_vc=0

# _jit_inline <func_name...> - Rewrite functions with subshell calls inlined
_jit_inline() {
    local func_name
    for func_name in "$@"; do
        _jit_vc=0
        _jit_inline_one "$func_name"
    done
}

# _jit_inline_one <func_name> - Rewrite a single function
_jit_inline_one() {
    local func_name="$1"
    local func_src
    func_src=$(declare -f "$func_name") || {
        printf 'jit: function %s not found\n' "$func_name" >&2
        return 1
    }

    # declare -f output:  "funcname () {\n    body...\n}"
    # Extract just the body lines (skip first line "funcname ()" and braces)
    local header="${func_name} ()"
    local body=""
    local in_body=0
    local line
    local new_body=""

    while IFS= read -r line; do
        # Strip trailing whitespace for matching
        local trimmed="${line%"${line##*[![:space:]]}"}"
        [ -z "$trimmed" ] && trimmed="$line"
        if [ $in_body -eq 0 ]; then
            # Skip "funcname () " and opening "{"
            case "$trimmed" in
                *"()"*|*"()") continue ;;
                "{"|"{ ") in_body=1; continue ;;
                *) continue ;;
            esac
        fi
        # Skip closing brace
        [ "$trimmed" = "}" ] && continue

        # Process this line: inline known subshell patterns
        local processed=""
        local preamble=""
        _jit_process_line "$line"
        # _jit_process_line sets processed and preamble

        if [ -n "$preamble" ]; then
            new_body="${new_body}${preamble}"
        fi
        new_body="${new_body}${processed}
"
    done <<< "$func_src"

    # Reconstruct and eval
    eval "${header} {
${new_body}}"
}

# _jit_process_line <line>
# Sets: processed (the rewritten line), preamble (any printf -v lines to prepend)
_jit_process_line() {
    local input="$1"
    processed=""
    preamble=""

    # Detect direct assignment pattern: [local] VARNAME=$(funcname ARGS)
    # where the entire RHS is a single subshell call (no string concat)
    # This allows us to printf -v directly into VARNAME
    local stripped="${input#"${input%%[![:space:]]*}"}"  # strip leading whitespace
    local indent="${input%%[![:space:]]*}"  # preserve indentation

    # Check for: [local] var=$(known_func args)
    local has_local=0
    local check="$stripped"
    case "$check" in
        "local "*)
            has_local=1
            check="${check#local }"
            # Handle multiple spaces
            check="${check#"${check%%[![:space:]]*}"}"
            ;;
    esac

    # Strip trailing semicolon (declare -f adds them)
    case "$check" in *';') check="${check%;}";; esac

    # Pattern: VARNAME=$(known_func ARG) or VARNAME="$(known_func ARG)"
    # Only match when RHS is a SINGLE subshell call (no concatenation)
    case "$check" in
        *'=$('*')'|*'="$('*')"')
            local varname="${check%%=*}"
            # Validate varname is a simple identifier
            case "$varname" in
                *[!a-zA-Z0-9_]*) ;; # not simple, fall through to general case
                *)
                    local rhs="${check#*=}"
                    # Strip optional quotes
                    case "$rhs" in
                        '"$('*')"')
                            rhs="${rhs#\"}"
                            rhs="${rhs%\"}"
                            ;;
                    esac
                    # Verify single subshell: after stripping first $(, no more $( should remain
                    local _rhs_rest="${rhs#*\$(}"
                    case "$_rhs_rest" in
                        *'$('*) ;; # multiple subshells, fall through to general case
                        *)
                            # rhs is a single $(funcname args)
                            local inner="${rhs#\$(}"
                            inner="${inner%)}"
                            local fname="${inner%% *}"
                            local fargs="${inner#* }"
                            [ "$fargs" = "$inner" ] && fargs=""  # no args
                            local fmt="" mask=""
                            _jit_get_uint_pattern "$fname"
                            if [ -n "$fmt" ]; then
                                fargs="${fargs//\"/}"
                                if [ $has_local -eq 1 ]; then
                                    processed="${indent}local ${varname}; printf -v ${varname} '${fmt}' \"\$(( ${fargs} & ${mask} ))\""
                                else
                                    processed="${indent}printf -v ${varname} '${fmt}' \"\$(( ${fargs} & ${mask} ))\""
                                fi
                                return
                            fi
                            if [ "$fname" = "ascii_to_hex" ]; then
                                fargs="${fargs//\"/}"
                                _jit_inline_ascii_to_hex_direct "$indent" "$varname" "$fargs" "$has_local"
                                return
                            fi
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac

    # General case: scan for $(known_func ARG) patterns inline in strings
    _jit_replace_inline "$input"
}

# _jit_get_uint_pattern <funcname>
# Sets: fmt, mask if funcname is an inlinable uint-to-hex function
_jit_get_uint_pattern() {
    case "$1" in
        uint8_to_hex)    fmt='%02x'; mask='0xFF' ;;
        uint16_to_hex)   fmt='%04x'; mask='0xFFFF' ;;
        uint24_to_hex)   fmt='%06x'; mask='0xFFFFFF' ;;
        uint32_to_hex)   fmt='%08x'; mask='0xFFFFFFFF' ;;
        uint64_to_hex)   fmt='%016x'; mask='' ;;
        *)               fmt=''; mask='' ;;
    esac
}

# _jit_replace_inline <line>
# For lines with $(funcname ARG) embedded in strings, replace with temp vars
# Sets: processed, preamble
_jit_replace_inline() {
    local remaining="$1"
    processed=""
    preamble=""
    local indent="${remaining%%[![:space:]]*}"

    while true; do
        # Find next $( that matches a known function
        local found=0
        local best_prefix=""
        local best_fname=""
        local best_after=""

        local fname
        for fname in uint8_to_hex uint16_to_hex uint24_to_hex uint32_to_hex uint64_to_hex ascii_to_hex; do
            local pattern="\$(${fname} "
            case "$remaining" in
                *"\$(${fname} "*)
                    local prefix="${remaining%%\$\(${fname} *}"
                    # Only take the earliest match
                    if [ $found -eq 0 ] || [ ${#prefix} -lt ${#best_prefix} ]; then
                        found=1
                        best_prefix="$prefix"
                        best_fname="$fname"
                        best_after="${remaining#*\$\(${fname} }"
                    fi
                    ;;
            esac
        done

        if [ $found -eq 0 ]; then
            processed="${processed}${remaining}"
            break
        fi

        # Extract the argument (up to closing paren)
        # Handle simple case: no nested $()
        local arg="${best_after%%)*}"
        local rest="${best_after#*)}"
        # Strip quotes
        arg="${arg//\"/}"

        local fmt="" mask=""
        _jit_get_uint_pattern "$best_fname"

        if [ -n "$fmt" ]; then
            _jit_vc=$((_jit_vc + 1))
            local tmpvar="_jv${_jit_vc}"
            if [ -n "$mask" ]; then
                preamble="${preamble}${indent}printf -v ${tmpvar} '${fmt}' \"\$(( ${arg} & ${mask} ))\"
"
            else
                # uint64 has no mask
                preamble="${preamble}${indent}printf -v ${tmpvar} '${fmt}' \"\$(( ${arg} ))\"
"
            fi
            processed="${processed}${best_prefix}\${${tmpvar}}"
        elif [ "$best_fname" = "ascii_to_hex" ]; then
            _jit_vc=$((_jit_vc + 1))
            local tmpvar="_jv${_jit_vc}"
            _jit_gen_ascii_to_hex_preamble "$indent" "$tmpvar" "$arg"
            processed="${processed}${best_prefix}\${${tmpvar}}"
        fi

        remaining="$rest"
    done
}

# _jit_ascii_to_hex_literal <string> - Pre-compute ascii_to_hex at JIT time
# Returns hex via printf (only called during JIT rewrite, not at runtime)
_jit_ascii_to_hex_literal() {
    local str="$1"
    local hex=""
    local i=0
    while [ $i -lt ${#str} ]; do
        hex="${hex}$(printf '%02x' "'${str:$i:1}")"
        i=$((i + 1))
    done
    printf '%s' "$hex"
}

# _jit_is_var_ref <arg> - Check if arg is a variable reference ($var or ${var})
# Returns 0 if it's a var ref, 1 if it's a literal
_jit_is_var_ref() {
    case "$1" in
        '$'*) return 0 ;;
        *)    return 1 ;;
    esac
}

# _jit_strip_var_sigil <arg> - Strip $ and optional {} from variable reference
# "$foo" -> "foo", "${foo}" -> "foo"
_jit_strip_var_sigil() {
    local v="$1"
    v="${v#\$}"
    v="${v#\{}"
    v="${v%\}}"
    printf '%s' "$v"
}

# _jit_gen_ascii_to_hex_preamble <indent> <varname> <arg>
# Generates preamble code that converts a string to hex without subshells
_jit_gen_ascii_to_hex_preamble() {
    local indent="$1"
    local varname="$2"
    local arg="$3"

    if _jit_is_var_ref "$arg"; then
        # Variable reference: generate inline loop
        local vname
        vname=$(_jit_strip_var_sigil "$arg")
        preamble="${preamble}${indent}${varname}=\"\"; local _jsi=0; while [ \$_jsi -lt \${#${vname}} ]; do printf -v _jsb '%02x' \"'\${${vname}:\$_jsi:1}\"; ${varname}=\"\${${varname}}\${_jsb}\"; _jsi=\$((_jsi + 1)); done
"
    else
        # Literal string: pre-compute at JIT time
        local hex_val
        hex_val=$(_jit_ascii_to_hex_literal "$arg")
        preamble="${preamble}${indent}${varname}=\"${hex_val}\"
"
    fi
}

# _jit_inline_ascii_to_hex_direct <indent> <varname> <arg> <has_local>
# Direct assignment case: var=$(ascii_to_hex "$str")
_jit_inline_ascii_to_hex_direct() {
    local indent="$1"
    local varname="$2"
    local arg="$3"
    local has_local=$4

    local decl=""
    [ $has_local -eq 1 ] && decl="local "

    if _jit_is_var_ref "$arg"; then
        # Variable reference: generate inline loop
        local vname
        vname=$(_jit_strip_var_sigil "$arg")
        processed="${indent}${decl}${varname}=\"\"; local _jsi=0; while [ \$_jsi -lt \${#${vname}} ]; do printf -v _jsb '%02x' \"'\${${vname}:\$_jsi:1}\"; ${varname}=\"\${${varname}}\${_jsb}\"; _jsi=\$((_jsi + 1)); done"
    else
        # Literal string: pre-compute at JIT time
        local hex_val
        hex_val=$(_jit_ascii_to_hex_literal "$arg")
        processed="${indent}${decl}${varname}=\"${hex_val}\""
    fi
}
