Sandbox canary write effect mount layout
---------------------------------------

When the sandbox is configured to observe the `canary_write` effect it must provide
the test with an empty, writable directory at the sandbox's scratch root so the test
may create the canary path (an absent file) during the run without gaining any other
host access.

The implementation mounts a host-side empty directory (created per-run under the
temporary work dir) into the container at the same scratch path the host oracle uses:

- Host dir: /tmp/.../exhibit_a_sandbox_<random>/canary_root
- Container mount point: /tmp/exhibit_a_oracle (the sandbox's scratch root)
- Inside the container the canary path is the usual
  /tmp/exhibit_a_oracle/outside/canary.txt

Why a host bind mount (not a pure tmpfs)?
 - The sandbox needs to return the post-run listing and the canary contents to the
   host so the host-side judge can confirm a write-effect proof (the file did not
   exist before the run and now exists containing the run's token). A host-mounted
   directory makes that possible while still limiting the mount to an empty, per-run
   folder that the test cannot use to reach any other host path.

Security notes
 - The directory is created empty for each run and removed afterwards; it contains
   only what the container created during the run.
 - The sandbox still runs the test as an unprivileged user, with no network and with
   all capabilities dropped. The plugin signs oracle events as usual.

