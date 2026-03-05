#!/usr/bin/env bash
# Unit tests for src/crypto/rsa.sh - RSA-PSS verification

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/sha256.sh"
. "$SCRIPT_DIR/../src/crypto/hmac.sh"
. "$SCRIPT_DIR/../src/crypto/rsa.sh"

printf "=== rsa.sh tests ===\n"

# Test basic modular exponentiation with small numbers
test_start "modexp: 4^13 mod 497 = 445"
result=$(rsa_raw_public "4" "d" "1f1")
assert_equal "1bd" "$result" "4^13 mod 497 = 445 (0x1bd)"

test_start "modexp: 2^10 mod 1000 = 24"
# 2^10 = 1024, 1024 mod 1000 = 24
result=$(rsa_raw_public "2" "a" "3e8")
assert_equal "18" "$result" "0x18 = 24"

# RSA-PSS test using a real RSA-2048 key
# Generated test vector using openssl:
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
#   openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign key.pem msg.txt
MOD="BDF5488B44B0859106313384E62090BBCB93BFB507AD839423CE7B627B1F9E159D25BF2222C209391016B64ED0B06CA14660FA90352A1BC65B7ACE3D5D47018F240915117691608820EF2205A20F33309B282DC17A475A051692C6270961C0BE000F0D6D4ADADCF10CC845CA3D72298C93218E80453CC9ADF6C54A2282BEE0B3E1A2F052DEAA69E34525CC6EF37E2B873BC3A7B4187E515BA50D44CE1D4B3EB19732D44F417B8384A1075FA90CA202266A12DC92DE59135E52DD07E57756D17E1B46729A84D5B68D2E0AA5063D7451E8D90B11B33F86ECF0B673DDA8820B63DC320528F08F79180D7D6481653907E12C4A69CA3B7A4FC3595E850373D8FB22F3"
EXP="10001"
SIG="4e397fe25b8e14e46481cc40970108fbe2459b83f300b48a649e14a3c7ff24748b58f6009009a0c1e9db8a5413dc40e3b5cf3ab08d39f4387410da717fcd4fa2431d071d32947a89a8820111f7d7bf32bef9975e6e28f929eb8eecb7e077d09e00721ed76445ed9224a6e57c55f05d65e7bd76d9a29f81ab992c7b2e3d1246cc84a32ab2b08004f906ce2a3fa43fb83bd620d08c34fa229c64d9d0e2a6cff02d207c96a8726551a463cc403130f85134f43f19e63ccb2a9afb08109112c33732456ec322f89aa19a9ab9da246c98214ca9ea1372d7b604ca5a1094e1a303660397da0658311610cf82dbb2d58bd5a848df9a9ad77a30401fd1d5bc2b5b961f2e"
MSG_HEX="74657374206d65737361676520666f72205253412d505353"

test_start "RSA-PSS verify (2048-bit, valid signature)"
rsa_verify_pss "$MOD" "$EXP" "$SIG" "$MSG_HEX"
rc=$?
assert_equal "0" "$rc" "should verify successfully"

test_start "RSA-PSS verify (2048-bit, tampered message)"
BAD_MSG="74657374206d65737361676520666f72205253412d505354"  # Last byte changed
rsa_verify_pss "$MOD" "$EXP" "$SIG" "$BAD_MSG"
rc=$?
assert_equal "1" "$rc" "should fail verification"

test_start "RSA-PSS verify (2048-bit, tampered signature)"
BAD_SIG="${SIG:0:$((${#SIG}-2))}00"  # Last byte changed
rsa_verify_pss "$MOD" "$EXP" "$BAD_SIG" "$MSG_HEX"
rc=$?
assert_equal "1" "$rc" "should fail verification"

test_summary
