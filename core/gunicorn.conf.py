# Category downloads and DNS validation may exceed the default 30 seconds.
# Keep a single worker: network mutations use a process-local lock.
timeout = 120
