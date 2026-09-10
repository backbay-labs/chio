# Final relocated candidate installation

Claude r5 0dd0d906 and OpenClaw r6 a79dbffa installed from copied archives offline with empty caches; packaged entrypoint syntax checks passed. Pi ec609539 installed using its documented public peer 0.85.1 first, followed by the local plugin, both with nested dependency strategy and scripts disabled. Its cache was empty before the public host install. These installation checks do not claim host activation or full acceptance.

The first generic Pi plugin-only offline command failed with ENOTCACHED because it omitted the documented required public peer. This exposed a root bundle instruction error, not an archive runtime defect. Both the failed attempt and corrected installation are retained. No legacy-peer-deps workaround or repack was used.

Disposable consumer dependency trees and npm caches are omitted; exact archive identities, lockfiles, commands, outputs and driver source are retained. They are not required private inputs to installation.
