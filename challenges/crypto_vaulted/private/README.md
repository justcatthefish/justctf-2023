If running locally does not work and you can see the following in the Docker container logs:

```
[W][2023-05-30T14:53:08+0000][1] createCgroup():56 mkdir('/sys/fs/cgroup/NSJAIL.8', 0700) failed: Read-only file system
[E][2023-05-30T14:53:08+0000][1] initParent():425 Couldn't initialize cgroup 2 user namespace for pid=8
```

That means that your system does not support cgroups v2 required by the Nsjail config.

In such a case, please comment out those lines in `private/nsjail.cfg`:

```diff
-use_cgroupv2: true
+#use_cgroupv2: true
-cgroup_pids_max: 10
+#cgroup_pids_max: 10
-cgroup_mem_max: 67108864 # 64 MiB -- Note that too low will make it swapped to disk which is bad
+#cgroup_mem_max: 67108864 # 64 MiB -- Note that too low will make it swapped to disk which is bad
-cgroup_cpu_ms_per_sec: 900
+#cgroup_cpu_ms_per_sec: 900
```
