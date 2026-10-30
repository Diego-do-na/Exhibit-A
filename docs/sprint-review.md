# Revisión de cierre del sprint — Exhibit A

Fecha: 2026-10-28 · Rama: `sprint-close` (sobre `main` @ `89c74b7`) · Revisor: Claude (evidencia propia, comandos ejecutados).
Los reportes de los agentes no se tomaron como evidencia. Todo lo marcado "no verificado" no se pudo comprobar sin red, claves ni modelos de pago.

## 1. Resumen ejecutivo

**Veredicto: CERRAR CONDICIONADO.** El motor de prueba funciona de verdad: el caso Starlette CVE-2023-29159 produce `proven` (fails_on=vulnerable, passes_on=fixed, runs=3, bypass 2/0) dentro del sandbox, y el caso corregido no produce ningún `proven`.
Pero (1) `main` no está verde (1 test obsoleto), (2) `python -m bench` con los defaults reales **falla de punta a punta**, (3) el oráculo se deja engañar por eventos falsificados y por symlinks plantados por el test, y (4) **ninguna llamada a un modelo real se ha hecho jamás**: las grabaciones de replay son `hand-authored`, y el SPEC §15 exige que "resultados y demo vengan de modelos Meta".
Sin resolver (4) no hay demo honesta ante las reglas de la hackathon; (2) y (3) deben arreglarse o declararse límites antes del 4 de noviembre.

## 2. Evidencia de ejecución (FASE 3)

| Check | Comando | Resultado |
|---|---|---|
| Docker | `docker info` | OK (Colima, Docker 29.9.2) |
| Suite completa | `.venv/bin/python -m pytest -q -rfsxE` | **371 passed, 1 failed, 0 skipped** en 72 s. Fallo: `tests/test_models_config.py::test_meta_provider_is_explicitly_not_built_yet` = stale conocido (T031). Los 4 tests Ollama se ejecutaron (Ollama local con llama3.1:8b estaba activo) y pasaron. |
| Caso vulnerable | `python -m exhibit_a.cli run --case bench/corpus/starlette-cve-2023-29159 --replay --out <tmp>` | `proven: 1`, `fix_verified=True`, 4.6 s. verdict.json: fails_on=vulnerable, passes_on=fixed, runs=3, bypass tried=2 succeeded=0, provenance entry_point=`StaticFiles.__call__`. fix.patch: `commonprefix` → `commonpath`. |
| Portabilidad (T029) | `grep -rnE '/Users\|/private\|/tmp\|/var/folders'` en el paquete | Solo `/tmp/exhibit_a_oracle/outside/canary.txt`, que es una ruta **dentro del contenedor**, no del host. Sin rutas del host. ✔ |
| Caso corregido | igual con `-fixed` | `proven: 0, discarded_unproven: 1`. Ledger: baseline ok → exploit escrito → `verdict: test passed and the canary was never read: nothing was proven`. Es un descarte genuino, **no** un `env_failure`. ✔ |
| Sandbox (flags reales) | test-sonda ejecutado con `sandbox.run` | uid 501 (no root), red inaccesible, `/etc` y `/usr` no escribibles, solo `/tmp` (tmpfs) y `/workspace` escribibles, CapEff=0, NoNewPrivs=1, memoria 536870912 (512 MB), pids.max 64, cpu.max 50000/100000, sin docker.sock. ✔ |
| Replay | `ReplayMiss` si falta la llave; ambos casos corren en `--replay` sin grabador | Llaves coinciden con lo que genera el loop hoy ✔. `record.py` usa `pip install --target` ✔. Sin Starlette vendorizado en git (solo `LICENSE.starlette.md`, `case.json`, `baseline_test.py`, `record.py`, `replay.jsonl`). `runs/` (ignorado por git) conserva clones locales viejos. |
| Benchmark | `python -m bench --corpus bench/corpus/starlette-cve-2023-29159 --out X` | `IsADirectoryError` (exige el archivo `case.json`, no el directorio). |
| | `... --corpus bench/corpus/starlette-cve-2023-29159/case.json` | **Crash**: `FileNotFoundError: .../Exhibit-A/https:/github.com/encode/starlette` (`Path(case.repo)` con URL). Caso `-fixed`: mismo origen, falla en `_pick_source_file`. rc=1. |
| | `python -m bench --synthetic --corpus bench/corpus/synthetic.json --out X` | Funciona, tabla con 5 ablaciones. **Son números guionizados, no mediciones.** |
| Vista en vivo | `python -m exhibit_a.live.server --ledger <ledger> --port 8765` | `/` 200 HTML; `/api/runs`, `/api/summary` (20 eventos, línea sospechosa `staticfiles.py:172`), `/api/events`, `/events` SSE con `?replay=1`. Detenida al terminar. Detalle menor: el resumen muestra "Baseline: 0 passed, 0 failed" porque el evento no lleva conteos. |
| Presupuesto/live/totales | `pytest tests/test_run_live.py tests/test_run_budget.py tests/test_run_totals.py` | 9 passed. Aborta limpio con `BudgetExceeded` (ledger en disco), totales impresos (`cost_usd`, `tokens_in/out`, veredictos), default `ollama`/`llama3.1:8b` (costo 0). Con proveedor falso, sin llamadas en vivo. |
| Higiene | grep de claves en `git ls-files` y en `git log -p --all`; búsqueda de `.env` en todo el historial | Sin hallazgos. `.gitignore` cubre `.env`, `.env.*`, `runs/`, `.venv/`. |
| Co-authored-by | `git log --format=%B \| grep -i '^Co-authored-by'` | 25 líneas: Cursor 15, Copilot 7, Claude 3. |
| Git | `git status`, `git worktree list`, `git branch -a` | main limpio, un solo worktree. **Rama huérfana `backup/T039-copilot-record`** (1 commit propio, `ab5cb02`). |

### Prueba de trampas al oráculo (3.4)

App segura con confinamiento léxico (`abspath`+`commonpath`), ejecutada con `run_oracle` (host) y `SandboxRunner` (Docker). Script: `scratchpad/cheats/drive.py` (fuera del repo).

```
honest_control      passed  effect=False  → "nothing was proven"                         RECHAZA ✔
cheat_direct_read   failed  effect=True prov=False → "no application code on the stack"  RECHAZA ✔
cheat_forge_events  failed  effect=True prov=True  → "reached through an entry point"    ENGAÑADO ✘
cheat_symlink       failed  effect=True prov=True  → "reached through an entry point"    ENGAÑADO ✘
```
(igual en host y en sandbox). Los tests del repo `tests/test_oracle_eval.py` (5 passed) cubren solo lectura directa y sink directo.

## 3. Tabla de las 54 tareas

Fuente: auditoría de solo lectura (`git log --grep`, diff neto de cada merge, lectura de tests). Agente = prefijo de commit o bitácora; todos los commits llevan autor git `Diego_dona`. "Test real": sí / débil / no / n/a.

| ID | Agente | ¿Scope OK? | ¿Test real? | Notas |
|---|---|---|---|---|
| T001–T010 | n/i (sin ID en commits) | sí; T006/T010 listan `cli.py` (ya es paquete); T010 tocó `pyproject.toml` | sí (T006 débil: asserta el placeholder) | sin línea en bitácora (log "iteration 2") |
| T011 | agy | sí | n/a | |
| T012 | claude | sí | n/a | |
| T013 | Copilot | sí | n/a | |
| T014 | cursor-agent | sí | n/a | bitácora con `<did>`/`<left>` sin rellenar |
| T015 | agy | sí | n/a | |
| T016 | claude | sí | n/a | CI no excluye e2e/sandbox sin marca docker |
| T017 | Copilot | sí | sí | |
| T018 | claude | sí | sí | |
| T019 | claude | sí | débil | el merge no añadió test nuevo |
| T020 | claude | sí | sí | módulo entero con `skipif` sin Docker |
| T021 | assistant | **fuera**: `tests/sandbox_internal_tests.py` | débil | `pytest.skip` en env_failure; memoria solo `rc != 0` |
| T022 | claude | sí | sí | |
| T023 | claude | fuera (menor): fixture `async_app` | sí | |
| T024 | Muse | sí | sí | |
| T025 | Muse | sí | sí | |
| T026 | claude | fuera: `loop/runner.py`, `loop/__init__.py` | sí | |
| T027 | claude | fuera: `loop/runner.py`, `sandbox/runner.py`, `test_sandbox_events.py` (bitácora: ampliado con OK del usuario) | sí | **Confirmado**: canary real, `:ro`, tmpfs en el padre, probado en Docker |
| T028 | claude | sí | sí | **Confirmado**: los flags cambian el comportamiento (`pipeline.py:201,262,361,367`) |
| T029 | claude | sí | sí | portable confirmado por grep |
| T030 | Muse | sí | débil | contiene el test obsoleto que hoy falla |
| T031 | Muse | fuera: `models/config.py` | sí | rompió el test de T030; endpoint/precios UNVERIFIED |
| T032 | Copilot | sí | sí | |
| T033 | Muse | sí | sí | 4 tests solo "no lanza" |
| T034 | assistant | sí | sí | |
| T035 | Copilot | sí | débil | `skip` sin Ollama; asserta `isinstance(dict)` |
| T036 | Muse | fuera: `docs/reference/sandbox.md` (commit mal etiquetado) | sí | |
| T037 | Muse | fuera: `tests/test_e2e_cve.py` | débil | **Confirmado**: `--provider/--model` no existen en el parser; tests usan `Namespace` y `FakeRunner` en host |
| T038 | Muse | sí | sí | proveedor con precio real, ledger en disco |
| T039 | Copilot | sí | débil | commit sin ID; `>= 0` en parte, pero cruza con `Ledger.totals` |
| T040 | assistant | sí | débil | **Confirmado**: `Path(case.repo)` con URL → crash (reproducido). Bitácora lo registra como "T054" |
| T041 | Copilot | sí | **no** | **Confirmado**: monkeypatch de `make_pipeline`, `run_benchmark`, `write_results`, `render_table`; replay vacío |
| T042 | cursor-agent | sí | sí | línea de bitácora con espacio inicial |
| T043 | cursor-agent | sí | sí | |
| T044 | Copilot | fuera: `cli/run.py` (23 líneas) | débil | **Confirmado**; `pip install` en el host; `run.tree` obsoleto en case.json |
| T045 | cursor-agent | sí | débil | el rojo/verde final corre en host (`run_oracle`); sin marca docker; espacio inicial |
| T046 | Muse | fuera: directorio hermano `-fixed/` | débil | el test acepta cualquier no-proven (incluye env_failure); hoy sí da `discarded_unproven` |
| T047 | agy | sí | sí | |
| T048 | Copilot | fuera: `loop/pipeline.py` | sí | zip no se descomprime (declarado) |
| T049 | assistant | sí | débil | `skipif` Docker; sin prueba de socket; ensucia `os.environ`; espacio inicial |
| T050 | assistant | sí | n/a | commit etiquetado "T036"; bitácora lo registra como T036; falta su línea |
| T051 | Muse | sí | n/a | espacio inicial |
| T052 | Muse | sí | n/a | espacio inicial; ya obsoleto (dice que el adaptador no está conectado) |
| T053 | assistant | sí | n/a | espacio inicial |
| T054 | assistant | sí | n/a | informe afirma un "benchmark smoke" que no está entre los comandos ejecutados y que hoy crashea |

## 4. Hallazgos

Parches propuestos en texto; **ninguno aplicado**.

### Críticos

**C-1 · Ninguna salida de modelo real; replay "hand-authored".** (SPEC §15: "Results and demo come from Meta models".)
Evidencia: `bench/corpus/*/replay.jsonl` → `"model": "hand-authored"`, `tokens_in/out: 10/10`, `latency_ms: 1`. El `hypothesis` del adversario en el caso `-fixed` ya cita `commonpath` (escrito sabiendo el fix). El ledger de la demo muestra `model: hand-authored`.
Impacto: la demo valida el *motor*, no que un modelo Meta pueda hacer el trabajo; presentarlo como resultado de modelos violaría la regla. Meta API: UNVERIFIED (no hay clave aquí).
Arreglo: (a) grabar al menos una corrida real (`RecordingProvider`) con Ollama local (llama3.1:8b, ya disponible) y otra con un modelo Meta cuando haya clave; (b) etiquetar en README/demo el replay como "grabación escrita a mano". Esfuerzo: M.

### Altos

**A-1 · El oráculo acepta eventos falsificados.** Evidencia: `cheat_forge_events` (arriba). El test escribe en `EXHIBIT_A_EVENTS` (montado `:rw` en `sandbox/runner.py:159`) una línea con stack falso y hace `assert False` → `proven`.
Parche: firmar cada evento con HMAC cuya clave viva solo en el proceso del orquestador y se entregue al plugin por un canal que el test no lea (no por env/archivo), o ejecutar el test con otro uid que no pueda escribir el archivo y que el plugin escriba por un fd heredado/pipe abierto antes de importar el test. Mínimo: documentarlo como límite. Esfuerzo: M–L.

**A-2 · Symlink plantado por el test produce falso `proven`.** Evidencia: `cheat_symlink` contra app segura léxicamente. El hook usa `realpath` (`oracle/plugin.py:~181`), por lo que ve la lectura a través del symlink.
Parche: dejar `allowed/` fuera del alcance de escritura del test (crearlo con el contenido y montarlo `:ro`) y, en el plugin, registrar si algún componente de la ruta pedida es symlink creado durante la ejecución (`os.lstat` en el evento `open`) y marcar el evento `via_symlink`; `_judge` debe tratarlo como sin procedencia. Esfuerzo: M.

**A-3 · `python -m bench` con los defaults reales no funciona.** Evidencia: ver tabla (crash `FileNotFoundError: .../https:/github.com/encode/starlette`; además `--corpus` exige el archivo). `loop_pipeline.py` usa `Path(case.repo)`, fija `test_baseline.py` (el corpus usa `baseline_test.py`) y no pasa `requirements`.
Parche: resolver el árbol desde el directorio del `case.json` (`run.*`) o fallar con mensaje claro si `repo` es URL; leer `run.baseline_test` y `run.requirements`; aceptar directorio en `--corpus`; añadir test con el `case.json` real y runner falso. Esfuerzo: M.

**A-4 · `main` no está verde.** `tests/test_models_config.py:147` espera `ValueError("not built yet")`; `config.py:101` registra `meta`. AGENTS.md exige verde.
Parche: reemplazar el test por uno que construya `RoleConfig(provider="meta", ...)` con clave falsa en env y verifique `MetaProvider`, y añadir `meta` al set de `test_registry_lists_the_builtin_providers`. Esfuerzo: S (requiere excepción de scope).

**A-5 · T041: el test del CLI de bench no prueba nada del loop.** `tests/test_bench_cli.py:44-47` mockea todo. Parche: test que ejecute `main()` sobre un corpus mínimo con replay válido y runner falso y verifique filas y ledger. Esfuerzo: S.

**A-6 · `--provider/--model` no existen (T037).** Solo `--budget-usd` en `cli/parser.py`. El modo live solo usa Ollama por default; no se puede elegir Meta desde el CLI. Parche: `run.add_argument("--provider")`, `("--model")` y un test que llame `main([...])`. Esfuerzo: S.

**A-7 · Bitácora corrupta.** `docs/common.md`: T014 es placeholder; la línea "T054 added bench/loop_pipeline" es de T040; la línea "T036 added docs/reference/sandbox.md" es de T050; faltan T040 y T050; 6 líneas con espacio inicial (T049, T052, T053, T045, T054-bench, T042); una línea en blanco intermedia. T001–T010 sin línea. Regla del repo: no reescribir historia → añadir líneas nuevas `- T040 …`, `- T050 …`, `- T014 …` y corregir los espacios en un commit humano. Esfuerzo: S.

### Medios

- **M-1 · Pip en el host (T044/T045).** `cli/run.py:~82` ejecuta `pip install --target` en el host con red antes del sandbox; los sdist pueden ejecutar código. El rojo/verde del e2e corre en el host (`run_oracle`), y los e2e no llevan marca `docker`/`integration` (CI los ejecuta). Parche: marcar los e2e, ejecutar vía `SandboxRunner`, instalar con `--only-binary=:all:`. Esfuerzo: M.
- **M-2 · Tests de sandbox con `skipif`/`pytest.skip` si no hay Docker** (`test_sandbox_events/security/limits/image`, `sandbox_internal_tests`), prohibido por AGENTS.md. Hoy no se saltó ninguno (Docker activo). Parche: fixture que haga `pytest.fail` si `docker info` falla. Esfuerzo: S.
- **M-3 · Guard de T046 laxo.** `tests/test_e2e_cve_fixed.py:46-52` acepta `env_failure`. Parche: asertar `verdict == "discarded_unproven"`. Esfuerzo: S.
- **M-4 · T054 (acceptance) afirma un benchmark smoke que no se ejecutó** (ver A-3). Reescribir con la salida real de esta revisión. Esfuerzo: S.
- **M-5 · Rama huérfana `backup/T039-copilot-record`** con un commit no mergeado (`ab5cb02 Fix Starlette replay source install`). Revisar y borrar. Esfuerzo: S.
- **M-6 · `_judge` privado importado** por `loop/runner.py` (acoplamiento; reportado en T027). Exponer una función pública `judge()`. Esfuerzo: S.

### Bajos

- Paquete: `test_exploit.py` conserva `_inline` sin uso, un comentario "fixture removed" y una línea con espacio; cosmético.
- El evento `exploit_written` del ledger guarda la ruta absoluta del host (el *paquete* no; el ledger sí).
- El resumen de la vista en vivo muestra "0 passed, 0 failed" en el baseline.
- La imagen base trae `GPG_KEY` (clave pública de Python) en el entorno del contenedor; no es secreto, pero un chequeo de "sin secretos" por nombre lo marcará.
- T033: 4 tests sin assert; T049 ensucia `os.environ`; `test_sandbox_limits.py` importa `src.exhibit_a...`.
- Documentos obsoletos: `docs/bench/benchmark.md` L115/L130 (adaptador "no conectado"); `tests/…` del tablero listan `cli.py` inexistente.
- El primer commit del repo (`Initial commit`, 2026-10-26, autor distinto) es anterior al período de construcción (27 oct); hay que poder explicarlo (README vacío/plantilla).
- Límites declarados del oráculo (ver A-1/A-2 y GUIDE §6): el archivo de eventos es escribible desde el proceso del test; solo se observa `open()` del canary (lecturas por otros medios no se ven → falso negativo, no falso positivo); loops que sobreescriben `create_task` (uvloop) y `call_soon` no se enlazan.

## 5. Coherencia documentación vs. realidad (FASE 4)

- SPEC §12 dice "CLI: `run` wired to replay cases; live providers not yet fully wired" → coherente.
- AGENTS.md "Current state: oracle and Starlette baseline still run as host child processes … T026/T027 in progress" → **desactualizado**: tras T026/T027/T044 el baseline y el exploit del caso Starlette corren en el sandbox (verificado), aunque `pip install` sigue en el host.
- AGENTS.md dice que SCAN y SLICE no existen y el `scan` del CLI es placeholder → coherente.
- `docs/bench/benchmark.md` obsoleto (ver bajos). `docs/reference/sprint2-acceptance.md` ver M-4.
- Siguen **UNVERIFIED**: endpoint y `response_format` de la API de Meta, precios, tres clases de vulnerabilidad finales (solo path traversal está realizada: 1 de 3), ingestión multimodal (no construida), modelo concreto por rol, términos de datos del proveedor.
- SPEC §4 punto 5 / §8: superficie PR-diff = placeholder; CVE reachability, attack-surface map, GitHub Action, SCAN y SLICE: no construidos.

## 6. Lo que NO está verificado

- Cualquier llamada a Meta Model API u otro proveedor remoto (sin clave/red; prohibido).
- Una corrida live con Ollama de punta a punta (solo se corrieron los 4 tests de integración Ollama y los tests con proveedor falso).
- Comportamiento de CI en GitHub (el workflow nunca corrió allí según la bitácora).
- `docker inspect` en caliente: se verificó dentro del contenedor (cgroups, uid, caps, escritura) y por lectura de los flags de `docker run`, no con `docker inspect` de un contenedor vivo.
- Estabilidad (flaky) a largo plazo: solo 3 repeticiones por corrida.
- Historial T001–T010: sin agente identificable.
- Que el canary esté `:ro` se verificó por código y por el test del repo, no con un intento de escritura propio.

## 7. Arreglos priorizados antes del 4 de noviembre

| # | Arreglo | Esfuerzo |
|---|---|---|
| 1 | C-1: grabar una corrida real (Ollama ya; Meta si hay clave), etiquetar el replay actual como escrito a mano | M |
| 2 | A-3: reparar `python -m bench` sobre el corpus real + test real (A-5) | M |
| 3 | A-4: dejar `main` verde (test de Meta) | S |
| 4 | A-2 + A-1: bloquear symlinks y firmar/aislar eventos; si no alcanza, declarar el límite en README y demo | M–L |
| 5 | A-6: flags `--provider/--model` | S |
| 6 | M-2/M-3: tests de sandbox que fallen en vez de saltarse; guard `discarded_unproven` | S |
| 7 | M-1: instalar dependencias dentro de un paso aislado / `--only-binary` | M |
| 8 | A-7, M-4, M-5, docs obsoletos | S |
| 9 | Congelar features el 2 de nov (SPEC §12); demo/README/X el 3; búfer el 4 | — |
