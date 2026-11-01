# Ablation table

Every proof component and every oracle provenance layer is load-bearing, or the
row says plainly that it had no extra effect on the current attack set. A green
cell still means "nothing could be proven", never "safe". The sandbox that runs
untrusted tests is isolated and resource-limited, never "100% safe".

This table is **replay only**: no live model call. Red-team attacks
(`spikes/redteam`) and labelled corpus exploits go through `run_oracle` on the
host path. Loop ablations that do not change a single oracle judgement
(`no_differential`, `no_defender`) are scored from the full-oracle pass; they
are not a second model run.

The oracle layer switch is test-only (`run_oracle(..., disabled_layers=...)` /
`disable_oracle_layers`). The CLI has no flag for it and never sets
`EXHIBIT_A_DISABLED_LAYERS`. Layers: `L14_witness`, `L1_manifest`, `L2_admission`, `L3_app_tree`, `L4_guard`, `L5_dir_fd`, `L6_route_access`, `L7_canary_links`. Layer 14 is T114's OS-level
witness; the host path has no supervisor, so the `probe_L14_witness` row is the
judge-level stand-in (plugin saw the effect, the OS did not).

Cost is the committed recording total attributed to a case, not money spent
generating this table. False-proof counts include labelled flaky corpus exploits
whose outcome can differ between passes; a one-count shift without a named
attack is that noise, not a new hole.

<!-- BEGIN GENERATED: python -m bench.ablation_table -->
| configuration | false proofs | true proofs | missed true proofs | cost (USD) | what attack got through |
|---|---|---|---|---|---|
| `loop:baseline` | 162 | 53 | 0 | 0.0000 | `attack_forged_frame_filename`, `attack_forged_frame_same_line`, `attack_write_app_module`, `attack_modify_import_restore`, `attack_differential_bypass`, `attack_forge_events`, `attack_key_introspection`, `attack_symlink_recheck`, and 128 more — new vs full |
| `loop:failing_test_only` | 104 | 52 | 1 | 0.0597 | `attack_key_introspection`, `attack_symlink_recheck`, `attack_exec_canary_from_test`, `attack_exec_test_thread`, `attack_exec_marker_write`, `attack_exec_path_shim`, `attack_exec_native_system`, `attack_exec_raw_fork_exec`, and 75 more — new vs full |
| `loop:full` | 21 | 49 | 4 | 0.0597 | `attack_dependency_monkeypatch`, `attack_exec_r1_cell_tamper`, `attack_exec_r5_app_binding`, `attack_sql_r1_forge_events`, `attack_sql_r5_app_binding`, `attack_connect_r5_app_binding`, `attack_dos_r1_forge_events`, `attack_dos_r5_app_binding`, and 4 more |
| `loop:no_defender` | 21 | 49 | 4 | 0.0597 | single-run oracle judgements are unchanged; this flag applies to the fix/bypass steps of the loop |
| `loop:no_differential` | 21 | 49 | 4 | 0.0597 | single-run oracle judgements are unchanged; this flag applies to the fix/bypass steps of the loop |
| `oracle:no_L14_witness` | 19 | 49 | 4 | 0.0597 | `probe_L14_witness` — new vs full |
| `oracle:no_L1_manifest` | 20 | 49 | 4 | 0.0597 | no additional stable attack on the current attack set (other layers still hold; defense in depth) |
| `oracle:no_L2_admission` | 18 | 49 | 4 | 0.0597 | no additional stable attack on the current attack set (other layers still hold; defense in depth) |
| `oracle:no_L3_app_tree` | 21 | 49 | 4 | 0.0597 | `probe_L3_app_tree_change` — new vs full |
| `oracle:no_L4_guard` | 18 | 49 | 4 | 0.0597 | no additional stable attack on the current attack set (other layers still hold; defense in depth) |
| `oracle:no_L5_dir_fd` | 19 | 48 | 5 | 0.0597 | no additional stable attack on the current attack set (other layers still hold; defense in depth); newly missed: `attack_os_open_dir_fd` |
| `oracle:no_L6_route_access` | 16 | 49 | 4 | 0.0597 | `attack_key_introspection`, `probe_L6_route_access` — new vs full |
| `oracle:no_L7_canary_links` | 22 | 49 | 4 | 0.0597 | `attack_symlink_recheck` — new vs full |
<!-- END GENERATED -->
