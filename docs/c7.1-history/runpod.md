> Documento storico: descrive il proprio checkpoint, non le istruzioni correnti.
> Per implementare usare il [design corrente](../c7.1/design.md); per la provenienza vedere la [mappa](README.md).

# RunPod procedure

Read [current authorization](status.md) and the relevant
[C7.1 design](design.md) sections before provider work.
There is currently no provider or spending authorization. Readiness and
algorithm choices do not themselves authorize a pod or a production retry.
The [separate calibration plan](c71-calibration.md) is an authorization
proposal only, not permission to acquire weights or create a paid machine.

## Authorized pod lifecycle

Use [the repository harness](../../scripts/runpod_harness.sh) for future runs
that have received the required owner GO. Create paid pods with provider-side
`--stop-after` or `--terminate-after` deadlines; the harness help shows the
creation pattern. No selective production retry is allowed without separate
authorization. Production records are create-new and append-only, including
failed or interrupted attempts.

The harness commands are:

```text
scripts/runpod_harness.sh list
scripts/runpod_harness.sh status POD_ID
scripts/runpod_harness.sh pause POD_ID
scripts/runpod_harness.sh delete POD_ID --confirm POD_ID
```

`pause` releases the GPU but retains billable volume storage. `delete`
permanently terminates the pod and its non-network-volume data; preserve required
evidence before deletion and account separately for any surviving storage.

## Repository synchronization and credentials

On each new pod, synchronize repository files and small tracked evidence only
with Git push/pull against the GitHub HTTPS remote
`https://github.com/okrame/volta-zk.git`. Fetch/clone public source anonymously.
Do not use `gh`, Git-over-SSH, SCP/rsync, repository archives or credentials
copied/exported from the workstation. Verify the clean SHA after every pull.
Generated weights, setup and large run artifacts stay pod-local unless the
active design explicitly provides otherwise.

Supply authentication only through a repository-scoped, expiring fine-grained
RunPod Secret `VOLTA_GITHUB_TOKEN`, with repository Contents read/write access.
Never put it in a remote URL, Git config, shell history, command argument or
tracked/untracked file. The harness uses its own askpass path to keep the token
out of those locations.

Before compilation or asset generation, run:

```text
scripts/runpod_harness.sh git-preflight
```

This checks a clean checkout, the HTTPS origin, anonymous reads and an
authenticated dry-run push. After committing only small evidence, publish to a
unique pod branch with `scripts/runpod_harness.sh git-push runpod/POD_ID/LABEL`.
Use [build procedures](build-and-test.md) for compilation and cleanup; the active
design controls the actual workload and complete resource accounting.

Historical runbooks describe past campaigns. Their GO decisions, transport
exceptions, hardware profiles and retry permissions do not authorize C7.1.
