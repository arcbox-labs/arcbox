# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.5](https://github.com/arcboxlabs/arcbox/compare/v0.6.4...v0.6.5) (2026-08-11)


### Features

* **cli:** template catalog verbs and the presets rename (CORE-107) ([#602](https://github.com/arcboxlabs/arcbox/issues/602)) ([518cd46](https://github.com/arcboxlabs/arcbox/commit/518cd46cde5291bf4b5b7be8eed7950d0d2767a5))
* **sandbox:** enforce template ready probes on boot and warm restore (CORE-107) ([#600](https://github.com/arcboxlabs/arcbox/issues/600)) ([3f01be9](https://github.com/arcboxlabs/arcbox/commit/3f01be960c25e5b20678c895e5253249ea08ecc4))
* **sandbox:** implement snapshot promotion into templates (CORE-107) ([#595](https://github.com/arcboxlabs/arcbox/issues/595)) ([9bf0ae8](https://github.com/arcboxlabs/arcbox/commit/9bf0ae8d90ed874c01848f4b2913cd54c107ff16))
* **sandbox:** prewarm builds and template warm-restore on create (CORE-107) ([#599](https://github.com/arcboxlabs/arcbox/issues/599)) ([898f645](https://github.com/arcboxlabs/arcbox/commit/898f645ab58b463fabb9c7b9d0f20f4d4e7dcdeb))
* **sandbox:** resolve catalog templates in Create with pinned keys and default merge (CORE-107) ([#597](https://github.com/arcboxlabs/arcbox/issues/597)) ([1b42544](https://github.com/arcboxlabs/arcbox/commit/1b425446125aeebc529cda81cdf622740ddc0afa))
* **sdk:** arcbox — the native Rust SDK, phase 1 (lifecycle core) ([#603](https://github.com/arcboxlabs/arcbox/issues/603)) ([90f9fa8](https://github.com/arcboxlabs/arcbox/commit/90f9fa8d3beedd65ba06385d89dc45d66b0a0a68))
* **sdk:** commands surface for the Rust SDK ([#606](https://github.com/arcboxlabs/arcbox/issues/606)) ([9b55a70](https://github.com/arcboxlabs/arcbox/commit/9b55a70b53ceb576e3b35e58173cd3ef0685aa7b))
* **sdk:** files, ports, snapshots and events for the Rust SDK ([#608](https://github.com/arcboxlabs/arcbox/issues/608)) ([86bc3c6](https://github.com/arcboxlabs/arcbox/commit/86bc3c6fe24fb25b23014635109cc5a50457e651))


### Bug Fixes

* **sandbox:** PATH-resolve the TAP-delete ip binary; prove caller-less cleanup releases host resources (CORE-19/20) ([#612](https://github.com/arcboxlabs/arcbox/issues/612)) ([5b5adfe](https://github.com/arcboxlabs/arcbox/commit/5b5adfe764938195ee163be954f4096c2afab23d))


### Performance Improvements

* **vmnet:** event-driven relay read path, drop the 1 kHz poll thread ([#596](https://github.com/arcboxlabs/arcbox/issues/596)) ([9f05e30](https://github.com/arcboxlabs/arcbox/commit/9f05e309bdb6153de6bcb4a7dabd1f62d04ba781))


### Tests

* **e2e:** template catalog scenario + the four bugs it caught; docs + proto freeze (CORE-107) ([#607](https://github.com/arcboxlabs/arcbox/issues/607)) ([6ccb5aa](https://github.com/arcboxlabs/arcbox/commit/6ccb5aa74fbd4d9db07c9045daab7e7611a46b34))


### Documentation

* **agents:** sync AGENTS.md with the shipped template catalog (CORE-107) ([#610](https://github.com/arcboxlabs/arcbox/issues/610)) ([17334a9](https://github.com/arcboxlabs/arcbox/commit/17334a9e7be7440c1900c8ad5097adf38bac8269))


### Continuous Integration

* hand the desktop bump to arcbox-desktop ([#601](https://github.com/arcboxlabs/arcbox/issues/601)) ([fa11e85](https://github.com/arcboxlabs/arcbox/commit/fa11e8591673eecff2d559aaf2d09cfb26784e1d))


### Miscellaneous Chores

* **cli:** retire the arcbox rename shim ([#554](https://github.com/arcboxlabs/arcbox/issues/554)) ([95b1edf](https://github.com/arcboxlabs/arcbox/commit/95b1edfcb872ccbac31c97406568ad074cfbb1d4))

## [0.6.4](https://github.com/arcboxlabs/arcbox/compare/v0.6.3...v0.6.4) (2026-08-10)


### Features

* **agent:** serve sandbox pause/resume over vsock (CORE-21) ([43de608](https://github.com/arcboxlabs/arcbox/commit/43de60802524f49c7a8e441e00d93d73020caa16))
* **api:** classify agent errors into the sandbox error registry (CORE-58) ([072c937](https://github.com/arcboxlabs/arcbox/commit/072c9376ec492eb122aa4ec906b8ad87e275f323))
* **api:** list sandbox exposed ports (CORE-102) ([#585](https://github.com/arcboxlabs/arcbox/issues/585)) ([e40e57a](https://github.com/arcboxlabs/arcbox/commit/e40e57af1005bdfe5f339abd22c511ad24f3bf81))
* **api:** real GetCapabilities + nested-virt fail-fast on Create (CORE-13) ([cb5ed3c](https://github.com/arcboxlabs/arcbox/commit/cb5ed3c3d02987ffdc8c3609677cd36b50f67aa3))
* **api:** real Pause/Resume + daemon-side transparent auto-resume (CORE-21) ([0f1a782](https://github.com/arcboxlabs/arcbox/commit/0f1a78234d510a4c754acd51049c5dd82bd4462a))
* **core:** AgentClient pause/resume RPCs (CORE-21) ([1874e39](https://github.com/arcboxlabs/arcbox/commit/1874e39e5d54d3b8e13ef4ad46282453c435b82d))
* **e2e:** idle auto-pause + SetLifecycle + capabilities scenario; docs (CORE-21/60/13) ([90216b2](https://github.com/arcboxlabs/arcbox/commit/90216b25b82b434251db57aa6ea3473edfe61ddb))
* **e2e:** pause / auto-resume / explicit-resume scenario (CORE-21) ([fdae9b5](https://github.com/arcboxlabs/arcbox/commit/fdae9b5d083b7d70bee92ddc60632fcd0a47da23))
* **rpc:** pause/resume vsock wire types (CORE-21) ([bea2938](https://github.com/arcboxlabs/arcbox/commit/bea2938115c82342e0c9f8894ae589f1f52a4d24))
* **sandbox:** implement template Build from a docker_ref source (CORE-107) ([#593](https://github.com/arcboxlabs/arcbox/issues/593)) ([a7db0d4](https://github.com/arcboxlabs/arcbox/commit/a7db0d44f2450e746ba692ad791585ace47c905b))
* **sandbox:** implement template Build from inline Dockerfile content (CORE-107) ([#594](https://github.com/arcboxlabs/arcbox/issues/594)) ([fd3bb9f](https://github.com/arcboxlabs/arcbox/commit/fd3bb9f22055cd13a9933b8675d1bc887c7b8955))
* **sandbox:** implement the filesystem verbs and process-plane queries (CORE-62) ([#582](https://github.com/arcboxlabs/arcbox/issues/582)) ([cad4fee](https://github.com/arcboxlabs/arcbox/commit/cad4fee2785bf0aae61df077ccb83792cb2a6be0))
* **sandbox:** network-identity-invariant snapshots ([#562](https://github.com/arcboxlabs/arcbox/issues/562)) ([4149fb1](https://github.com/arcboxlabs/arcbox/commit/4149fb1b4bfd021399398a98173348981f7114bf))
* **sandbox:** serve eligible creates from warm template snapshots ([#569](https://github.com/arcboxlabs/arcbox/issues/569)) ([d23c12b](https://github.com/arcboxlabs/arcbox/commit/d23c12b8b4c8c9a238e6ac6d2d4baa725e508fa2))
* **sandbox:** template catalog store with GC pins (CORE-107) ([#590](https://github.com/arcboxlabs/arcbox/issues/590)) ([82c8b65](https://github.com/arcboxlabs/arcbox/commit/82c8b651dfca672853bc2235cf4715163212f8db))
* **sandbox:** wire SetLifecycle end to end (CORE-60) ([ecdf7d2](https://github.com/arcboxlabs/arcbox/commit/ecdf7d21f5d89d09f7e8114c2160a0742e4657f4))
* **sandbox:** wire the template catalog RPCs end to end (CORE-107) ([#592](https://github.com/arcboxlabs/arcbox/issues/592)) ([a92fb13](https://github.com/arcboxlabs/arcbox/commit/a92fb136ef5ff0e64c437bd28fcbf887d624ecf7))
* **vm:** idle detection + on_idle policy and re-armable TTL deadlines (CORE-21/60) ([d5b2dff](https://github.com/arcboxlabs/arcbox/commit/d5b2dff5b81c9fcd4e5d7a7e06b57d91283b6935))
* **vm:** sandbox pause/resume on the same id (CORE-21) ([a244ce2](https://github.com/arcboxlabs/arcbox/commit/a244ce256df775fe1f6827037bab6e5eba37ddb6))


### Bug Fixes

* **agent:** disambiguate exec ENOENT failures ([62aa0c4](https://github.com/arcboxlabs/arcbox/commit/62aa0c491e4fe044f8a0c7de7724ddf0122cc3c7))
* **ci:** harden the SDK publish jobs against the review findings ([ef4e411](https://github.com/arcboxlabs/arcbox/commit/ef4e4112d4ba087b2f3283af58e76f3599328934))
* **ci:** install with --frozen so a release tag's version bump is not fatal ([76ae8ee](https://github.com/arcboxlabs/arcbox/commit/76ae8ee0d9c97202b800ddb24ab075740b138fc7))
* **ci:** pin the publish jobs' actions and drop their cache/credential surface ([2fb3528](https://github.com/arcboxlabs/arcbox/commit/2fb3528e2b52bc5472eac82151293a13d013ed7a))
* **cli:** clarify component and boot versions ([134da85](https://github.com/arcboxlabs/arcbox/commit/134da85966e5a1a6ba33f4d5aa94b54e8d0b8257))
* **cli:** classify machine and sandbox failures ([9256795](https://github.com/arcboxlabs/arcbox/commit/925679513221ae4dcac0e825155073a959fecb73))
* **cli:** complete debug guidance fallbacks ([052d392](https://github.com/arcboxlabs/arcbox/commit/052d392dc319307a0c919e9ebeb7d77ee48bdf2e))
* **cli:** preserve raw-mode output and debug guidance ([28591dd](https://github.com/arcboxlabs/arcbox/commit/28591dd00f87ab804de086fd55885b72886ffaa8))
* **cli:** render actionable command failures ([85abe57](https://github.com/arcboxlabs/arcbox/commit/85abe57c84a025681fc8a8ef879e4ae8dd3b30d9))
* **cli:** resolve CORE-91/92/93/94/95/98 production audit findings ([#577](https://github.com/arcboxlabs/arcbox/issues/577)) ([56567d1](https://github.com/arcboxlabs/arcbox/commit/56567d12034b6519666f0a639a223bc6edc24194))
* **cli:** restore top controls and sanitize ANSI ([dc37582](https://github.com/arcboxlabs/arcbox/commit/dc375825e62e7025f55da16f38bbeace4bf4669f))
* **e2e:** apply the cold-download READY budget to the sdk_py harness too ([277a1dd](https://github.com/arcboxlabs/arcbox/commit/277a1dd224f2b2a163670d9aae80ad525960ec1a))
* **e2e:** apply the cold-download READY budget to the sdk_ts harness too ([9984dcf](https://github.com/arcboxlabs/arcbox/commit/9984dcf518209b4d2c9a520f3df8d0363973e5ec))
* **e2e:** budget the sandbox smoke's cold runtime-binary download ([8b5dfad](https://github.com/arcboxlabs/arcbox/commit/8b5dfadba4815428c4a0adb4815332ea9ccda2a0))
* **e2e:** drop the stray doc bullet from the sdk_ts READY budget comment ([d856408](https://github.com/arcboxlabs/arcbox/commit/d85640812fadb1330f25d608fd84291b88d19d67))
* **e2e:** seed guest runtime binaries into the generation directory ([4b2041b](https://github.com/arcboxlabs/arcbox/commit/4b2041bb873b4f2a74343275ff89ea09e81eefa7))
* **exec:** preserve actionable resource errors ([63fc728](https://github.com/arcboxlabs/arcbox/commit/63fc728ced56a1642fb9044530a4908d69bf43a0))
* **release:** resume partial crates.io publishes ([#548](https://github.com/arcboxlabs/arcbox/issues/548)) ([34a5e64](https://github.com/arcboxlabs/arcbox/commit/34a5e641aa91e5f47a63e92efdef0b0d53c4b7cd))
* **sandbox:** abort resume when the Resuming commit is not durable ([01dd386](https://github.com/arcboxlabs/arcbox/commit/01dd38659c5a1125f331c8dde13d2d27fdc06dc5))
* **sandbox:** address the lifecycle-knobs review findings ([5bcd4cb](https://github.com/arcboxlabs/arcbox/commit/5bcd4cbd987c574b8ee169f2a258d01fbe40ac2b))
* **sandbox:** classify file read/write errors on the file channel ([#586](https://github.com/arcboxlabs/arcbox/issues/586)) ([b79304a](https://github.com/arcboxlabs/arcbox/commit/b79304a5b525e5e5421af34d3f606e679f72e8c7))
* **sandbox:** close the idle-pause -&gt; resume network-finalization race ([45cd0e6](https://github.com/arcboxlabs/arcbox/commit/45cd0e6241abc81244939cc65c862ba60461c934))
* **sandbox:** fix the TAP-teardown race and surface swallowed RPC failures ([#567](https://github.com/arcboxlabs/arcbox/issues/567)) ([49d7119](https://github.com/arcboxlabs/arcbox/commit/49d711934e6c5928d02a5380b33c2ea656493975))
* **sandbox:** keep paused_at stable across failed resumes; prove the resumed TAP ([4036c21](https://github.com/arcboxlabs/arcbox/commit/4036c21aa21ffd953991a5521f44af4219cecf4d))
* **sandbox:** survive the pause-commit-to-journal-clear crash window ([4189097](https://github.com/arcboxlabs/arcbox/commit/4189097ae56beda443c4ac9bd33e8091ee3ab683))
* **vm:** gate dm-snapshot CoW on device-mapper usability, not binary existence ([253a55e](https://github.com/arcboxlabs/arcbox/commit/253a55e1e6167f1eba851ce1889ccbbbafa9d052))


### Performance Improvements

* **net:** batch guest-bound frame writes with sendmsg_x (ABX-313) ([943d9cd](https://github.com/arcboxlabs/arcbox/commit/943d9cd0cfd458282b6482ccfe6b9a036ab78279))
* **sandbox:** cold-start probe + restore fast path round 1 ([#555](https://github.com/arcboxlabs/arcbox/issues/555)) ([1b4b766](https://github.com/arcboxlabs/arcbox/commit/1b4b766906262f7ffa86acb8977a633f014464c2))
* **sandbox:** eBPF TCX datapath for invariant sandbox NAT ([#566](https://github.com/arcboxlabs/arcbox/issues/566)) ([46ef5a3](https://github.com/arcboxlabs/arcbox/commit/46ef5a369ca6dec1ab681dcb22380b507e4cc85d))
* **sandbox:** gate READY on agent vsock readiness and back off the connect poll ([#559](https://github.com/arcboxlabs/arcbox/issues/559)) ([6d8ab5f](https://github.com/arcboxlabs/arcbox/commit/6d8ab5f0b62af86bb53866a0fc0fd4dd5fbf6b95))
* **sandbox:** make boot readiness an event via guest vsock dial-out ([#560](https://github.com/arcboxlabs/arcbox/issues/560)) ([b8b7631](https://github.com/arcboxlabs/arcbox/commit/b8b7631b60eb9927ec8aeb91490e43e8d596abaf))
* **sandbox:** pre-warm restore slots behind an LRU snapshot pool ([#561](https://github.com/arcboxlabs/arcbox/issues/561)) ([6a08111](https://github.com/arcboxlabs/arcbox/commit/6a081119530efeca260cf0d8f253f482ec07c87f))
* **sandbox:** quiet microVM console + reconfig latency attribution + resolv on tmpfs (round 2) ([#558](https://github.com/arcboxlabs/arcbox/issues/558)) ([72f0e74](https://github.com/arcboxlabs/arcbox/commit/72f0e745d05b99d1ce775f13a9d9e0b5feabe33b))
* **sandbox:** self-sync the guest clock from ptp_kvm, off the restore path ([#568](https://github.com/arcboxlabs/arcbox/issues/568)) ([21c5232](https://github.com/arcboxlabs/arcbox/commit/21c52321b8fcaf9a4e228884ceb11ebcd1eddd65))
* **splicetcp:** batch guest-to-host frame reads with recvmsg_x (ABX-313) ([48413aa](https://github.com/arcboxlabs/arcbox/commit/48413aaa042c6d827cdb9c95e84ab0f47e086d99))
* **xnu-net:** iterator send API and live sysctl batch caps ([693b29b](https://github.com/arcboxlabs/arcbox/commit/693b29b8f48019131ddd82fa760275557aae2860))


### Tests

* **agent:** cover missing working directory ([2cd0810](https://github.com/arcboxlabs/arcbox/commit/2cd0810ef06ab7d770778cae3764c2510f957fcc))
* **e2e:** sdk_py harness — Python SDK hello world vs isolated daemon ([e5189b2](https://github.com/arcboxlabs/arcbox/commit/e5189b252833e43e43c4e7c5d6d9ab8f5274066d))
* **sandbox:** cover the terminal-state TTL guard and the List storage path ([9089f48](https://github.com/arcboxlabs/arcbox/commit/9089f48b6ef2a4d7e33bbcbad706ae84a63d5bff))


### Documentation

* **common:** record the batch-I/O contract the datapath now depends on ([f8e427b](https://github.com/arcboxlabs/arcbox/commit/f8e427b97eb6bff3405b2007c2dfe4729c8546fd))
* **sandbox:** pause/resume semantics + resolve the Pause-from-RUNNING ambiguity ([7efe0d5](https://github.com/arcboxlabs/arcbox/commit/7efe0d55d07a368f15cd7bfec328075db8c22591))
* **sdk:** mark the PyPI publish workflow pending and record the bootstrap caveats ([d240b92](https://github.com/arcboxlabs/arcbox/commit/d240b92b1e4277f7c41f1dd30f89a608e5c7eb05))
* **xnu-net:** pin XNU's silent recv truncation ([93bcf7d](https://github.com/arcboxlabs/arcbox/commit/93bcf7d0235ab9401534ec66c028e65cb38cf33b))


### Build System

* **sdk:** register @arcbox/sandbox as a release-please component ([d36184a](https://github.com/arcboxlabs/arcbox/commit/d36184a2f35f742b2f0f2a5e6df1143b87ea718e))
* **sdk:** register arcbox (Python) as a release-please component ([3b44845](https://github.com/arcboxlabs/arcbox/commit/3b44845028754de220e5a94bae54096daf6cddcf))


### Continuous Integration

* hash-pin actions and harden ci.yml per zizmor ([88d6220](https://github.com/arcboxlabs/arcbox/commit/88d62200ed5a10798848e8e7a412c4cd8856fb96))
* **sdk:** gate the TypeScript and Python SDKs on every PR ([f1cda25](https://github.com/arcboxlabs/arcbox/commit/f1cda25ff028a6a9cdb8ac898d58455faf1a6776))
* **sdk:** mirror the release uv build in the Python PR gate ([89a9323](https://github.com/arcboxlabs/arcbox/commit/89a932388e575e4d7afda43ebb07791c6e96951a))
* **sdk:** pin the PR gate's uv to the release toolchain range ([a7f5d51](https://github.com/arcboxlabs/arcbox/commit/a7f5d51c35f74c72750913080ecdb46f590ab3ed))
* **sdk:** publish @arcbox/sandbox to npm on the sdk-typescript tag ([bf9af74](https://github.com/arcboxlabs/arcbox/commit/bf9af74c1268b8e8296f2a2d496d72567c7b7754))
* **sdk:** publish arcbox (Python) to PyPI on the sdk-python tag ([cf33b8c](https://github.com/arcboxlabs/arcbox/commit/cf33b8c91732dd1288fe480d383a3881f75916a5))


### Miscellaneous Chores

* **assets:** pin boot assets 0.8.4 with the two-arch microvm kernel ([#572](https://github.com/arcboxlabs/arcbox/issues/572)) ([50e59cd](https://github.com/arcboxlabs/arcbox/commit/50e59cddb176a2b6b6e4a992e8a6dfa445a12c5b))
* **master:** release sdk-python 0.1.1 ([05e7cf5](https://github.com/arcboxlabs/arcbox/commit/05e7cf532bedfe84c948f8bed9db46019656ae43))
* **master:** release sdk-typescript 0.1.1 ([79f6170](https://github.com/arcboxlabs/arcbox/commit/79f61709db4fcf26b478d0d4bdeb7a1e0c252b96))

## [0.6.3](https://github.com/arcboxlabs/arcbox/compare/v0.6.2...v0.6.3) (2026-08-03)


### Features

* **rpc:** add the sandbox error registry (errors.proto) ([b3103c5](https://github.com/arcboxlabs/arcbox/commit/b3103c540e2ef64cff4b0bbd9186998092ff5dde))
* **rpc:** execution discovery and port readiness on the process plane ([3c8dec6](https://github.com/arcboxlabs/arcbox/commit/3c8dec63081f927368f19ab15e97d4382fde594e))
* **rpc:** filesystem path verbs (CORE-62) ([5f14b73](https://github.com/arcboxlabs/arcbox/commit/5f14b73207a41d14bb0c1f1b4364a4a563646e19))
* **rpc:** first-class template catalog (template.proto, CORE-21) ([7505f3b](https://github.com/arcboxlabs/arcbox/commit/7505f3ba225fdedcf42e1100d7de3d04d1f3ccd2))
* **rpc:** sandbox lifecycle — pause/resume, dual-knob timeouts, capabilities ([b081e99](https://github.com/arcboxlabs/arcbox/commit/b081e99e1c6c96b94e3fc7b88be03e8f92dd02ac))
* **runtime:** materialize guest runtime on Btrfs ([#529](https://github.com/arcboxlabs/arcbox/issues/529)) ([9315eb8](https://github.com/arcboxlabs/arcbox/commit/9315eb87554b8afa2884bdd0f165332a027d505b))
* **sdk:** ArcBox entry point and Sandbox handle ([fbf6ce4](https://github.com/arcboxlabs/arcbox/commit/fbf6ce4ecd99b5bd7082c0317e5526a8f98a6410))
* **sdk:** commands and files data-plane namespaces ([038b674](https://github.com/arcboxlabs/arcbox/commit/038b6741e501940435a69210fc33cb91f09e9c74))
* **sdk:** generate sandbox_v1 wire types via buf + protoc-gen-es ([2ec52ee](https://github.com/arcboxlabs/arcbox/commit/2ec52eed2fb47c6d1ba5507f6a34a0e512d0c149))
* **sdk:** hello-world e2e gate and README ([e85bf73](https://github.com/arcboxlabs/arcbox/commit/e85bf73023830c18da9b0d7a78eb23c9d94c72e2))
* **sdk:** scaffold @arcbox/sandbox package tooling ([5aa3134](https://github.com/arcboxlabs/arcbox/commit/5aa3134bd21d2e447e5ff1478f6c956e33bcf1b1))
* **sdk:** UDS Connect transport and typed error mapping ([9241860](https://github.com/arcboxlabs/arcbox/commit/9241860d1e8f2cfeb5fc02f25d6d5e3f852e2e30))


### Bug Fixes

* **migration:** make a migrated dev environment actually run, add --dry-run ([#520](https://github.com/arcboxlabs/arcbox/issues/520)) ([02d5692](https://github.com/arcboxlabs/arcbox/commit/02d569265286c923106410f124bb4178c78250ee))
* **rpc:** give SetLifecycle.on_idle explicit presence ([2e50089](https://github.com/arcboxlabs/arcbox/commit/2e50089744b5f0fdc552a31e885484107a1dd22b))
* **rpc:** make template default cmd/env suppressible in Create ([2a438f9](https://github.com/arcboxlabs/arcbox/commit/2a438f9ce17c4583ee2a3959e8b9fc2307a42ce0))
* **sdk:** clean up on failed create and widen the dispose not-found gate ([8aae4de](https://github.com/arcboxlabs/arcbox/commit/8aae4ded91afae0536ed96741f1b1931851afe50))
* **sdk:** honor ARCBOX_PROFILE when resolving the default socket ([31cf8e5](https://github.com/arcboxlabs/arcbox/commit/31cf8e5626cdc6cbdc723cf3a02e7de83bf151b0))
* **sdk:** include node types explicitly so the build config compiles ([18798cb](https://github.com/arcboxlabs/arcbox/commit/18798cba124759bc6c6da7423e072a4ba09806be))
* **sdk:** report retained-output truncation and deadline the signal RPC ([b0d05cf](https://github.com/arcboxlabs/arcbox/commit/b0d05cfae622ee22437355ff36df912ad49c4136))
* **sdk:** resolve the writeBytes default mode SDK-side ([2ca4c8c](https://github.com/arcboxlabs/arcbox/commit/2ca4c8c2a4b31fc4e394473e1219aeb8c1f8fa21))


### Code Refactoring

* **sdk:** resolve the sukka lint findings in handwritten code ([1611b15](https://github.com/arcboxlabs/arcbox/commit/1611b156622036045a2e97a10bc18712be41273a))


### Tests

* **e2e:** harness hook for SDK e2e ([1fcbf27](https://github.com/arcboxlabs/arcbox/commit/1fcbf27a5d18f4fb46c9d025c135099f19dd4a8f))


### Documentation

* **rpc:** pin the limits override contract's zero-subfield semantics ([dc92556](https://github.com/arcboxlabs/arcbox/commit/dc9255664415f54a0c17ba77afde85c68a3fe06d))
* **sandbox:** carry the limits zero-subfield semantics into the API doc ([a94d9ab](https://github.com/arcboxlabs/arcbox/commit/a94d9ab922028d1a15e024ff6234dfd4699b4e2e))
* **sandbox:** reflect the CORE-58 phase 1 contract additions ([34b4477](https://github.com/arcboxlabs/arcbox/commit/34b4477e8313d3c57654b6ac10c25cc96501205d))
* **sandbox:** untangle the limits aside from the override enumeration ([b8d4057](https://github.com/arcboxlabs/arcbox/commit/b8d4057eab4c78fe98cdc5dd22057d6f049a8575))


### Styles

* **sdk:** apply the biome formatter ([6c2aff2](https://github.com/arcboxlabs/arcbox/commit/6c2aff2dbde4b39ccbe3157c290a5160d4dd84bd))


### Miscellaneous Chores

* **sdk:** build with bunchee instead of tsc ([4a6fae7](https://github.com/arcboxlabs/arcbox/commit/4a6fae7fb0c64c3b2a46cbe516bce7af3adfb3af))
* **sdk:** swap prettier and typescript-eslint for biome and sukka ([4aab59f](https://github.com/arcboxlabs/arcbox/commit/4aab59f571c93be2a5c1fc5e477dd7f8de433d42))

## [0.6.2](https://github.com/arcboxlabs/arcbox/compare/v0.6.1...v0.6.2) (2026-08-03)


### Features

* **sandbox:** establish durable lifecycle records ([#538](https://github.com/arcboxlabs/arcbox/issues/538)) ([876c47c](https://github.com/arcboxlabs/arcbox/commit/876c47c62626d4a78286c0a085cf96b4d155e635))


### Bug Fixes

* **sandbox:** make create retries idempotent ([#536](https://github.com/arcboxlabs/arcbox/issues/536)) ([3c44f06](https://github.com/arcboxlabs/arcbox/commit/3c44f06bde1324fdf145f255b28504702e50cfb6))


### Code Refactoring

* **rpc,daemon,fleet:** prost becomes test support only (CORE-73 follow-up) ([#540](https://github.com/arcboxlabs/arcbox/issues/540)) ([3b24286](https://github.com/arcboxlabs/arcbox/commit/3b242865e2e8f7ef51f29f9dbff07726f0acd2fa))

## [0.6.1](https://github.com/arcboxlabs/arcbox/compare/v0.6.0...v0.6.1) (2026-08-03)


### Reverts

* **rpc:** roll the agent protocol back to 1 ([#537](https://github.com/arcboxlabs/arcbox/issues/537)) ([3502023](https://github.com/arcboxlabs/arcbox/commit/3502023d997ed9324fee4981168978e8b858edad))

## [0.6.0](https://github.com/arcboxlabs/arcbox/compare/v0.5.5...v0.6.0) (2026-08-02)


### ⚠ BREAKING CHANGES

* **api:** retire tonic from the daemon (CORE-68)
* **sandbox:** addressable executions, template-only API, plane split (CORE-54/55/56/57) ([#519](https://github.com/arcboxlabs/arcbox/issues/519))

### Features

* **agent:** gate the guest NFS export behind a host request (ABX-426) ([#512](https://github.com/arcboxlabs/arcbox/issues/512)) ([0330cc4](https://github.com/arcboxlabs/arcbox/commit/0330cc4bffda28e9e0d8808dd4d2cfd9cad7b774))
* **api:** serve the sandbox control plane over Connect (CORE-53) ([99e1758](https://github.com/arcboxlabs/arcbox/commit/99e175825ecc1a6a8baddb2bf81f70ec82ec0e1c))
* **daemon:** publish VM_STARTING/VM_READY/NETWORK_READY (CORE-67) ([8d52b12](https://github.com/arcboxlabs/arcbox/commit/8d52b129ee07843a86b73909a876a2701425493f))
* **daemon:** serve reflection from the Connect stack (CORE-53) ([1eeff6b](https://github.com/arcboxlabs/arcbox/commit/1eeff6b4a17d63dbf59386ec702089079811be5f))
* **daemon:** serve the sandbox API over Connect, gRPC, and gRPC-Web (CORE-53) ([33a9d5e](https://github.com/arcboxlabs/arcbox/commit/33a9d5ee3e9a92a7e50fcec70cb61d038b874321))
* **daemon:** show ~/ArcBox files as owned by the browsing user (ABX-427) ([#515](https://github.com/arcboxlabs/arcbox/issues/515)) ([d3b17d2](https://github.com/arcboxlabs/arcbox/commit/d3b17d29f1808e9a5a02a638eb06262424889fcf))
* **rpc:** generate the sandbox Connect surface with connectrpc + buffa (CORE-53) ([0c11969](https://github.com/arcboxlabs/arcbox/commit/0c11969db587038f61c202090c096ef589be1444))
* **sandbox:** addressable executions, template-only API, plane split (CORE-54/55/56/57) ([#519](https://github.com/arcboxlabs/arcbox/issues/519)) ([f014052](https://github.com/arcboxlabs/arcbox/commit/f014052962bd5450dbaff3700b61e5847f046ddb))


### Bug Fixes

* **api,daemon:** fail the exec pump toward EOF and gate the macOS assertion ([2fc781f](https://github.com/arcboxlabs/arcbox/commit/2fc781f4898fd4c2f80504a5fa22a3e50072b402))
* **api:** stream every setup-status update, not the newest snapshot ([b7bb651](https://github.com/arcboxlabs/arcbox/commit/b7bb65118d8252109d1ec2c233ac1d763c888d92))
* **daemon,api:** pin the h2 stream cap and tidy test-only dependencies ([7b93edc](https://github.com/arcboxlabs/arcbox/commit/7b93edc6bb01c104773b133dc45bed591ea0d015))
* **daemon:** arm the vm_running mirror before init, and stop over-promising ([01747dc](https://github.com/arcboxlabs/arcbox/commit/01747dcb2242b85f94ebea210dc971698178bd3e))
* **daemon:** bound NFS unmount time ([da06aed](https://github.com/arcboxlabs/arcbox/commit/da06aed2b224173bb1d0ea7ad7630e1eaa2aa472))
* **daemon:** make vm_running track the VM and a docker.sock bind fail startup ([03a09f9](https://github.com/arcboxlabs/arcbox/commit/03a09f9840a2c327a621bf17ebe7bfd8816384b7))
* **daemon:** unmount NFS before shutdown ([8b868ae](https://github.com/arcboxlabs/arcbox/commit/8b868aee0c7c1583a6e089d3407634658b386c7d))
* **helper:** use async fn syntax in the fs e2e test ([c8cdc1a](https://github.com/arcboxlabs/arcbox/commit/c8cdc1a37f768347495688d396d77287994afdb2))
* **rpc:** build the Connect descriptor set with protoc compat flags ([57e3837](https://github.com/arcboxlabs/arcbox/commit/57e38372d9f5d61215c3b25c3d00acfaa136a8eb))


### Code Refactoring

* **agent:** port the guest agent to buffa message types ([8e4a37c](https://github.com/arcboxlabs/arcbox/commit/8e4a37ce27925666b6df9083cef383bc4d6040df))
* **api,core:** retire tonic and the prost deps from the API layer ([b4b6f65](https://github.com/arcboxlabs/arcbox/commit/b4b6f65b9b679d96d119afedc334d2c8446173f0))
* **api:** generate the daemon surface with buffa and move Icon (CORE-68) ([2e9d670](https://github.com/arcboxlabs/arcbox/commit/2e9d670f7c09b83a5ecfbeeccbfd56ffb2671029))
* **api:** move Kubernetes and Migration onto Connect (CORE-68) ([d6fc295](https://github.com/arcboxlabs/arcbox/commit/d6fc295f8fc7080d5a3df377170a43363dadc96f))
* **api:** move Machine onto Connect (CORE-68) ([f6db17f](https://github.com/arcboxlabs/arcbox/commit/f6db17f24c7d9cbd46c59a4a0e82e6bbbff0794e))
* **api:** move Stats and System onto Connect (CORE-68) ([4f84914](https://github.com/arcboxlabs/arcbox/commit/4f849143303ac6ca26d15dca5bcd4b3721ce6493))
* **api:** retire tonic from the daemon (CORE-68) ([016fd01](https://github.com/arcboxlabs/arcbox/commit/016fd0102b06e247b09d256aee2a5d1545ab799c))
* **api:** single-type the machine and macos services on buffa ([86dd726](https://github.com/arcboxlabs/arcbox/commit/86dd7263b5b6b050dfe68be736c0e483ff06c353))
* **cli,docker,transport:** drop the dead arcbox-protocol deps ([57b88c4](https://github.com/arcboxlabs/arcbox/commit/57b88c471230f6d64fbe4efe3aaac6b7414fde2f))
* **cli:** drive interactive exec through a split Connect bidi stream (CORE-68) ([3b4d125](https://github.com/arcboxlabs/arcbox/commit/3b4d12593cc29fac037d9ca259488c8b3af3466d))
* **cli:** machine and macos commands on buffa types ([ff21b22](https://github.com/arcboxlabs/arcbox/commit/ff21b220998111930cee04ce7dfcd8e8c66bbae6))
* **cli:** move machine, system, migrate, and disk onto Connect (CORE-68) ([badd54a](https://github.com/arcboxlabs/arcbox/commit/badd54addbd15cc3ba8035b71fb1b7bd13b3c540))
* **cli:** move the remaining clients onto Connect (CORE-68) ([166d9e5](https://github.com/arcboxlabs/arcbox/commit/166d9e59bad7227084be4a2b22dad7584f8c1ab5))
* **cli:** sandbox and agent commands on buffa, delete the prost seam ([dbb24f2](https://github.com/arcboxlabs/arcbox/commit/dbb24f277cda309f4bfbf2deeac4c02a7acd3947))
* **cli:** start moving clients onto Connect (CORE-68) ([72857e7](https://github.com/arcboxlabs/arcbox/commit/72857e7abfbcf75cf26dfa63eb13718792ddb0c8))
* **cli:** system, disk, and kubernetes commands on buffa types ([e2b96f5](https://github.com/arcboxlabs/arcbox/commit/e2b96f5f263ffb5d3461abd1a3bf0b11bc3eca9c))
* **cli:** top and migrate commands on buffa types ([230b9bd](https://github.com/arcboxlabs/arcbox/commit/230b9bd69e5d6b2643dd112d9c3b0f5076d023df))
* **core,api:** port machine exec and stats to buffa end-to-end ([d2b4529](https://github.com/arcboxlabs/arcbox/commit/d2b452940b1b9ca3e294030aae159aa70ed7378f))
* **core,api:** port the kubernetes surface to buffa ([e7ef45c](https://github.com/arcboxlabs/arcbox/commit/e7ef45cc26ba2e29d9548345362089eb44e203b3))
* **core,api:** port the sandbox surface to buffa end-to-end ([2ba9f94](https://github.com/arcboxlabs/arcbox/commit/2ba9f943e8a85647179ba8223fb99eafe4e448ec))
* **core,api:** single-type system, migration, and the setup state on buffa ([225f9cc](https://github.com/arcboxlabs/arcbox/commit/225f9cc35ec0225ad5f12682aa0f09bff2108acd))
* **core:** fold the split arcbox_connect imports into one block ([5941358](https://github.com/arcboxlabs/arcbox/commit/5941358fc6e9e521c36bcfc18de9cc2cce386015))
* **core:** port the host agent channel to buffa message types ([3c25982](https://github.com/arcboxlabs/arcbox/commit/3c25982b2d8eb92522636f575e3d8ddf13f0f1e5))
* **docker:** drop the bind-and-serve wrapper that has no callers ([1c6d33d](https://github.com/arcboxlabs/arcbox/commit/1c6d33d592ffc9c65a840f7801c2c90b805f0a6b))
* **rpc,e2e:** decouple persisted JSON from generated proto types ([55d68b2](https://github.com/arcboxlabs/arcbox/commit/55d68b23e7aa99a4443a2b25778a18274586d9e5))


### Tests

* **core:** pin the no-Linux-VM contract for init's milestones ([cd810ce](https://github.com/arcboxlabs/arcbox/commit/cd810cee1e7dd96fc3c6478b5c0a603432ad10e5))
* **daemon:** prove one endpoint answers all three wire formats (CORE-53) ([2997db4](https://github.com/arcboxlabs/arcbox/commit/2997db4be26a90f1de82f55394f229babacb521a))
* **docker,proxy:** address review — drop the port TOCTOU, assert whole targets ([89a12c7](https://github.com/arcboxlabs/arcbox/commit/89a12c755d695269ec9bded0051d8a43f12d62aa))
* **docker:** assert requests reach dockerd unaltered ([34aaf8e](https://github.com/arcboxlabs/arcbox/commit/34aaf8e4ef39d4d2b97c631d8cc46cde64037958))
* **e2e:** add the smoke suite ([95d914b](https://github.com/arcboxlabs/arcbox/commit/95d914b1d84813e15f5e6238b566856da01a0350))
* **e2e:** add VirtioFS host-guest consistency checks ([930f697](https://github.com/arcboxlabs/arcbox/commit/930f697f05865fff09eaa2161ccaa2f16a5465c8))
* **e2e:** assert a plain JSON POST reaches the live sandbox API (CORE-53) ([90d3521](https://github.com/arcboxlabs/arcbox/commit/90d35215ac82bc1ff68976d98cbe6b70bd43b1fa))
* **e2e:** calibrate the boot budget and require both of its marks ([b068366](https://github.com/arcboxlabs/arcbox/commit/b06836633a91d529b46385269db3a22f3b01cd30))
* **e2e:** drive an interactive abctl PTY session end to end ([#527](https://github.com/arcboxlabs/arcbox/issues/527)) ([5c31677](https://github.com/arcboxlabs/arcbox/commit/5c31677a7609699784ee46c4e97f19b916cd3550))
* **e2e:** expose setup-phase timings from the readiness stream ([3f2ac46](https://github.com/arcboxlabs/arcbox/commit/3f2ac4600a76241e2235a73f1084f0de4664a1ed))
* **e2e:** fix two defects in the daemon lock suite found in review ([44d06ff](https://github.com/arcboxlabs/arcbox/commit/44d06ffbfa9e60ef53d280329e2c387e9b460b47))
* **e2e:** iperf3 throughput matrix (finds container-upload collapse + inbound gap) ([#461](https://github.com/arcboxlabs/arcbox/issues/461)) ([b816c7b](https://github.com/arcboxlabs/arcbox/commit/b816c7b79434645cf9c5e332c13203dd621ba954))
* **e2e:** IPv6-drop characterization + content-integrity coverage ([#462](https://github.com/arcboxlabs/arcbox/issues/462)) ([ea08fb3](https://github.com/arcboxlabs/arcbox/commit/ea08fb38b54a595a64b4968047ed7a94740437d1))
* **e2e:** pin the daemon lock lifecycle contract ([bc5037e](https://github.com/arcboxlabs/arcbox/commit/bc5037eb92db102e8177a4c6e06b85022b804994))
* **proxy:** cover the inbound accept path and the ICMP round trip ([0b6f376](https://github.com/arcboxlabs/arcbox/commit/0b6f3765486994938f33596fdc78f28bd027736a))
* **proxy:** run the ICMP round trip in CI instead of ignoring it ([8e8bfc0](https://github.com/arcboxlabs/arcbox/commit/8e8bfc0388f68db31326bdb1cb504b9e02cf39d5))


### Documentation

* **app:** correct which lock side makes SetupState::subscribe atomic ([95edb17](https://github.com/arcboxlabs/arcbox/commit/95edb17d238c3481d30adefaad83c0c03b0a5b63))
* **app:** record that restart_generation reports departures, not arrivals ([706c832](https://github.com/arcboxlabs/arcbox/commit/706c8320362b7480964dbdad86476da83d86cf97))
* **balloon:** host cost is the guest-touched high-water mark, not memory_mb ([4a3c274](https://github.com/arcboxlabs/arcbox/commit/4a3c27484faee7269ed12ad05c482dc72d5b20d7))
* **claude:** revise File I/O and idle-memory perf targets per measured reality ([68c3afd](https://github.com/arcboxlabs/arcbox/commit/68c3afddbb904c7c15756242f688cb178075fd92))
* **cli:** update stale `arcbox` invocations to `abctl` ([#510](https://github.com/arcboxlabs/arcbox/issues/510)) ([dd786da](https://github.com/arcboxlabs/arcbox/commit/dd786dae4aaa34321802d0871c908ed291e52963))
* **daemon:** correct shutdown budget ([ee4d4f8](https://github.com/arcboxlabs/arcbox/commit/ee4d4f8da18a27f5107fdf3dbcec3e17e587a8ac))
* **daemon:** make NETWORK_READY's description true in VM-host-only mode ([e02e0b2](https://github.com/arcboxlabs/arcbox/commit/e02e0b2cab4dcdd77bec2cc6a2c9bc1e7fbf8390))
* **readme:** cover the shipped feature surface ([#516](https://github.com/arcboxlabs/arcbox/issues/516)) ([2727072](https://github.com/arcboxlabs/arcbox/commit/272707275b7e1fb19b5deaf43cb42bf84757710c))
* **rpc,api:** true up the codec-boundary comments for this stage ([d8b0b62](https://github.com/arcboxlabs/arcbox/commit/d8b0b623d258375af71cdd39dbcb565843d0e527))
* **rpc,guest:** record the buffa single-type end state (CORE-73 B5) ([0589998](https://github.com/arcboxlabs/arcbox/commit/058999812fc3143823e18a6ef729c6885a2d6446))
* **rpc:** arcbox-connect now also feeds the guest agent's vsock frames ([0e3f816](https://github.com/arcboxlabs/arcbox/commit/0e3f816d3613e56b1ca548ada47790bfb3b06e75))
* **rpc:** fix the checklist cross-references the bots caught ([8ffc626](https://github.com/arcboxlabs/arcbox/commit/8ffc626f1010773a52fb3f6f594d2c6eb721bd6d))
* **rpc:** name reflection's descriptor set as the daemon's prost remnant ([bc0c03a](https://github.com/arcboxlabs/arcbox/commit/bc0c03ab0e573b318cab89d73383f770a17b4f3c))
* **rpc:** name the fleet prost consumer and the vsock wiring boundary ([ecf11af](https://github.com/arcboxlabs/arcbox/commit/ecf11af40c4f1f35205ace5b547511589bc8c58a))
* **rpc:** record the Connect surface in the agent handbook (CORE-53) ([0212859](https://github.com/arcboxlabs/arcbox/commit/0212859881f7f9b64386717908b644d9cce865c4))
* **rpc:** stop declaring the router's own add_service dead ([e3f8912](https://github.com/arcboxlabs/arcbox/commit/e3f89129512b612c6f16521fe5943c961344f5ca))
* **rpc:** true up the build script's host-codec claim ([6834c5a](https://github.com/arcboxlabs/arcbox/commit/6834c5a1beaeb32d7cddbf24f8bd98265fd03916))
* **rpc:** update arcbox-grpc's WKT comment to the post-serde rationale ([9a4df4c](https://github.com/arcboxlabs/arcbox/commit/9a4df4c89895676067585f9ff6ea6cb39fdc06f3))
* settled VirtioFS performance record (fs-perf-limits, CORE-48) ([#517](https://github.com/arcboxlabs/arcbox/issues/517)) ([dd17f42](https://github.com/arcboxlabs/arcbox/commit/dd17f4286a852dd61772c5c5debd689f4caf1aee))
* **test,ci:** correct two claims this suite's audit disproved ([6eddac7](https://github.com/arcboxlabs/arcbox/commit/6eddac716770334ae75120f5f6468ec19c064309))


### Build System

* **proto:** declare the sandbox package as a publishable buf module (CORE-53) ([d681cb0](https://github.com/arcboxlabs/arcbox/commit/d681cb08d59d0d02b3f82fb8cb3e76f9453e84c4))


### Continuous Integration

* **proto:** exempt the WKT image files the module split stops materializing ([1f511b8](https://github.com/arcboxlabs/arcbox/commit/1f511b8d96e53a666969a557bb039b577ea98bc2))

## [0.5.5](https://github.com/arcboxlabs/arcbox/compare/v0.5.4...v0.5.5) (2026-07-31)


### Features

* **cli:** abctl claude — coding-agent TUI in a sandbox ([bd558cd](https://github.com/arcboxlabs/arcbox/commit/bd558cdf7bbf9d6a5771d058d3203cb1c90bb616))
* **cli:** embedded sandbox image templates ([aa00154](https://github.com/arcboxlabs/arcbox/commit/aa001540284855e106c70ce4fb6bd08515fa4c36))


### Bug Fixes

* **cli:** do not wait for the parked stdin read when the runtime shuts down ([94c1ad5](https://github.com/arcboxlabs/arcbox/commit/94c1ad522ae983837c0bc8f6c01003b77ac35819))
* **cli:** end an exec session when the workload exits ([050ff66](https://github.com/arcboxlabs/arcbox/commit/050ff66f996734646f9bef2f454196e31c6804cb))
* **cli:** key the image layout cache on filesystem content, not image id ([75aaa6f](https://github.com/arcboxlabs/arcbox/commit/75aaa6f417e09ebea578e4d68ad4b17a6b7dcb86))
* **sandbox:** invalidate converted rootfs images when vm-agent changes ([df66e8c](https://github.com/arcboxlabs/arcbox/commit/df66e8c92a6ddad686f69cc5371b53be05d03ccc))
* **sandbox:** keep converted rootfs images that snapshots restore from ([3837c08](https://github.com/arcboxlabs/arcbox/commit/3837c08c6e96671b2b82a1eea2cc03162889b91b))
* **sandbox:** report an interactive workload's exit status when it exits ([9bcf94c](https://github.com/arcboxlabs/arcbox/commit/9bcf94c7907dc1a44022e0d0a7fc78def9e04358))
* **sandbox:** resolve docker images through an OCI layout export ([96740ca](https://github.com/arcboxlabs/arcbox/commit/96740ca3497c7516170ffb57ba6210b7ca86c55f))
* **vz:** build the Swift shim with SwiftPM's native build system ([19e46b7](https://github.com/arcboxlabs/arcbox/commit/19e46b748626cdc8432db3ec530c9df204013812))


### Code Refactoring

* **vm:** publish snapshots atomically instead of piecewise ([419b270](https://github.com/arcboxlabs/arcbox/commit/419b2705450fd0617ba0a5ab5d95bdf0dd776607))


### Miscellaneous Chores

* **assets:** bump boot assets to 0.6.13 (fuse spin-wait, CORE-48) ([#513](https://github.com/arcboxlabs/arcbox/issues/513)) ([098771c](https://github.com/arcboxlabs/arcbox/commit/098771c0bb65fea9ce6f59aa679187770ec65e2f))
* **tools:** bump Docker toolchain to latest stable versions ([#502](https://github.com/arcboxlabs/arcbox/issues/502)) ([a44178b](https://github.com/arcboxlabs/arcbox/commit/a44178b0729ec61a7100c4546144a8dbd73d72e9))

## [0.5.4](https://github.com/arcboxlabs/arcbox/compare/v0.5.3...v0.5.4) (2026-07-30)


### Bug Fixes

* **core:** disable the idle balloon — no macOS backend reclaims ballooned memory ([#504](https://github.com/arcboxlabs/arcbox/issues/504)) ([6cb174a](https://github.com/arcboxlabs/arcbox/commit/6cb174a005d1a5a9ba5a018c21e4d1dded6db060))


### Tests

* **e2e:** VirtioFS guest-vs-native benchmark driver ([#507](https://github.com/arcboxlabs/arcbox/issues/507)) ([4e5f676](https://github.com/arcboxlabs/arcbox/commit/4e5f676525f3d2f0426bc6f09eb1b63d73ff4ff4))

## [0.5.3](https://github.com/arcboxlabs/arcbox/compare/v0.5.2...v0.5.3) (2026-07-24)


### Bug Fixes

* **net:** detect and reap zombie fast-path flows on both legs ([dc0295e](https://github.com/arcboxlabs/arcbox/commit/dc0295e358fb00b1c70af7cae59e503d18d767bc))
* **net:** start the dead-flow deadline at solicitation, not the last guest frame ([bafee56](https://github.com/arcboxlabs/arcbox/commit/bafee564189f6e06da7e63dc40d7909c7f9e46bd))
* **virtio:** drop RX frames that don't fit the chain instead of truncating ([b341beb](https://github.com/arcboxlabs/arcbox/commit/b341bebe4ac7820fae4cc8212c08a5582bda4136))
* **virtio:** poison a chain on an out-of-RAM descriptor; update poll_rx docs ([f33337c](https://github.com/arcboxlabs/arcbox/commit/f33337c80efe707552326cb106cb69cd5339a986))


### Performance Improvements

* **agent:** expedite RCU grace periods to cut runc create ~8x (ABX-496) ([6e67d6f](https://github.com/arcboxlabs/arcbox/commit/6e67d6f2d432724d7b04a1569c75c2634e5c8ddd))
* **runtime:** exec the container runtime from a read-only block image (ABX-498) ([#499](https://github.com/arcboxlabs/arcbox/issues/499)) ([bde8fb0](https://github.com/arcboxlabs/arcbox/commit/bde8fb01a3f01503be1bec8457423a52c3b67018))
* **storage:** ext4 metadata volume for fsync-hot boltdb state (ABX-496) ([#497](https://github.com/arcboxlabs/arcbox/issues/497)) ([e4aca03](https://github.com/arcboxlabs/arcbox/commit/e4aca033b1eb7818601b48c71137711a24e1a6b5))


### Tests

* **e2e:** live validation of the host-networking reconciler ([#352](https://github.com/arcboxlabs/arcbox/issues/352)) ([696ea7f](https://github.com/arcboxlabs/arcbox/commit/696ea7f8a41dbae6f010386b9dcff9ffb864bd95))
* **e2e:** observe the removal before timing the sweep; pin the fail-safe ([d46dbcd](https://github.com/arcboxlabs/arcbox/commit/d46dbcd5be270feffd1b0a7e43d67a12ebac4570))


### Styles

* **e2e:** apply rustfmt to reconciler_teardown test ([f2a1050](https://github.com/arcboxlabs/arcbox/commit/f2a1050d4ba87421fe964891cbf4d1276276b784))


### Miscellaneous Chores

* **assets:** bump boot assets to 0.6.10 (FEX procfs fix, ABX-494) ([4b52760](https://github.com/arcboxlabs/arcbox/commit/4b52760046499b74dc7fd057a2d842f9462a3aca))

## [0.5.2](https://github.com/arcboxlabs/arcbox/compare/v0.5.1...v0.5.2) (2026-07-21)


### Bug Fixes

* **agent:** gate readiness on routing setup ([4edbdc8](https://github.com/arcboxlabs/arcbox/commit/4edbdc8d4d5a99c197ca3fda24004d8e92544343))
* **agent:** reconcile direct routing firewall rule ([564d73a](https://github.com/arcboxlabs/arcbox/commit/564d73ab815e436c6a745863b778a0f5e8c77b7f))
* **dns:** don't hold the forwarder write lock across blocking upstream I/O ([75310eb](https://github.com/arcboxlabs/arcbox/commit/75310eb0bf0d292b351f47c357a6018f084be530))
* **dns:** source-check forwarded replies and honor the query QTYPE ([4318422](https://github.com/arcboxlabs/arcbox/commit/4318422780a681c24a7777dc188ecf1edfdcffab))
* **dns:** validate upstream replies to close cache-poisoning window ([e5e8e18](https://github.com/arcboxlabs/arcbox/commit/e5e8e18cb460958a9ac7d08bac6d4b90d730a48a))
* **dns:** zero NSCOUNT and ARCOUNT in local-hostname responses ([6050d9d](https://github.com/arcboxlabs/arcbox/commit/6050d9d30d98558d35f2d82735199fa85af8065c))
* **doctor:** query container route as network ([d4274d4](https://github.com/arcboxlabs/arcbox/commit/d4274d47c7d7f466a69658428a2d9390bae217f6))
* **fs:** harden the passthrough FUSE server against hostile guests ([7aec6fd](https://github.com/arcboxlabs/arcbox/commit/7aec6fdc1ee0e87e9c71e1872c2ca04bb5de3f42))
* **net:** abort an inbound ActiveOpen handshake when the host peer disconnects ([7c683ee](https://github.com/arcboxlabs/arcbox/commit/7c683ee55fbc009c9261f1092f1bf55cbb76ff1a))
* **net:** add a zero-window persist probe to the download fast path ([b46b0dc](https://github.com/arcboxlabs/arcbox/commit/b46b0dcce16e2e9e0907bb3a45518dd0073f9537))
* **net:** bound half-closed flows with a FIN_WAIT2 idle timeout ([ff4c330](https://github.com/arcboxlabs/arcbox/commit/ff4c3300d254025078407f6cf2c21647277c6097))
* **net:** bound parked out-of-order segment count and drain in O(1) ([2111a5b](https://github.com/arcboxlabs/arcbox/commit/2111a5b94adcbf20c73a78dfab6bd5fef13923df))
* **net:** extend the zero-window persist probe to inline-owned flows ([22c29ca](https://github.com/arcboxlabs/arcbox/commit/22c29cad0bd7cc84e0f1d6ef0646ec95018f3b8d))
* **net:** half-close guest FIN instead of tearing the whole flow down ([d64aaec](https://github.com/arcboxlabs/arcbox/commit/d64aaec4459192a9875cf317157d5bc5c14959f7))
* **net:** let a retransmitted SYN-ACK's payload/FIN flow through ([3702fe9](https://github.com/arcboxlabs/arcbox/commit/3702fe94a54eab5cfa1b4698e211504a383b6337))
* **net:** park out-of-order upload segments instead of dropping them ([dc5edcc](https://github.com/arcboxlabs/arcbox/commit/dc5edcc9a0b286e4174c7339d1cf6bfa6bc3dcb9))
* **net:** re-ACK a retransmitted guest SYN on an established fast-path flow ([27e90f3](https://github.com/arcboxlabs/arcbox/commit/27e90f3f85ee005d52cd1c9913c10e162a6f0ee5))
* **net:** reject contained IP fragments that conflict byte-for-byte ([b69c776](https://github.com/arcboxlabs/arcbox/commit/b69c776ea97179eb1720bfa0ce7784c65133144c))
* **net:** reject overlapping IP fragments instead of last-write-wins ([05f248b](https://github.com/arcboxlabs/arcbox/commit/05f248b72db3eb73ccf7cf31af261c16c2ebb480))
* **net:** retry EINTR on the NIC datapaths instead of dropping / killing them ([610ada1](https://github.com/arcboxlabs/arcbox/commit/610ada1ef905cb590c10341d5fc26f06f089a458))
* **net:** treat ActiveOpen host EOF as half-close, RST the guest on reset ([90c8bcc](https://github.com/arcboxlabs/arcbox/commit/90c8bcc8a0b1431dcf0b885147897a5fba389774))
* **net:** validate IPv4 IHL and TCP data offset before parsing headers ([1d4d6c9](https://github.com/arcboxlabs/arcbox/commit/1d4d6c91ca4d475a0f9ac480da33d8b82f7e6216))
* **network:** allow direct container traffic ([d4fb502](https://github.com/arcboxlabs/arcbox/commit/d4fb5027c66c37b3ac21280f4cff951ea2a85c01))
* **route:** fall back to split container routes ([d027055](https://github.com/arcboxlabs/arcbox/commit/d0270553d858977b5935dcff06f1aa55af5dc2ba))
* **route:** replace conflicting gateway routes ([20714c9](https://github.com/arcboxlabs/arcbox/commit/20714c96c1800aaf55ae97d920dedc09367dda8e))
* **virtio:** interrupt the guest after a zero-length RX completion ([80f7639](https://github.com/arcboxlabs/arcbox/commit/80f763995966cdb4da38a2091eecdf9b910d59cf))
* **virtio:** return zero-capacity RX chains to the used ring instead of leaking ([2ee2645](https://github.com/arcboxlabs/arcbox/commit/2ee264500d93a0cc61fbf9fdd32c5e2bed1b7d60))


### Tests

* **dns:** echo the question in the fake upstream reply ([ffda1be](https://github.com/arcboxlabs/arcbox/commit/ffda1be157608508b11359445d2b08c7b450e5ca))
* **helper:** use a monotonic counter for unique fixture roots ([f74f1ab](https://github.com/arcboxlabs/arcbox/commit/f74f1ab034d9f01c2f64a008aa2222877586788f))
* lookup_rejects_path_traversal_names. 64 arcbox-fs tests pass; clippy+fmt clean. ([7aec6fd](https://github.com/arcboxlabs/arcbox/commit/7aec6fdc1ee0e87e9c71e1872c2ca04bb5de3f42))


### Miscellaneous Chores

* **master:** release fleet-agent 0.1.3 ([#406](https://github.com/arcboxlabs/arcbox/issues/406)) ([701eff6](https://github.com/arcboxlabs/arcbox/commit/701eff6d0beb78ab6308f8474c1d9451c60b5207))

## [0.5.1](https://github.com/arcboxlabs/arcbox/compare/v0.5.0...v0.5.1) (2026-07-21)


### Bug Fixes

* **helper:** retain strict dynamic validation ([3de5f4e](https://github.com/arcboxlabs/arcbox/commit/3de5f4e4978f4322c4820db4df2dd9679e70655c))
* **helper:** use valid dynamic code-signing flags ([9263b88](https://github.com/arcboxlabs/arcbox/commit/9263b88db27e0792be15bb652c6dfffd13e7b2b5))

## [0.5.0](https://github.com/arcboxlabs/arcbox/compare/v0.4.24...v0.5.0) (2026-07-20)


### ⚠ BREAKING CHANGES

* **helper:** security-framework peer auth + structured HelperError wire

### Features

* **helper:** give arcbox-helper an independent crate version ([172ae31](https://github.com/arcboxlabs/arcbox/commit/172ae31d926254b969cfb7a7001c93d304149561))
* **helper:** security-framework peer auth + structured HelperError wire ([8061ba5](https://github.com/arcboxlabs/arcbox/commit/8061ba5dd1c5ad0cd4d8f157608a175e59b7250c))


### Bug Fixes

* **helper:** clarify compatibility diagnostics ([a9affdd](https://github.com/arcboxlabs/arcbox/commit/a9affddb21519ac7862886c80ea60b8650f0e750))
* **helper:** dedicated DockerSocketOccupied error variant ([d0d16e5](https://github.com/arcboxlabs/arcbox/commit/d0d16e56189459fd8a3da2c913452927812d795e))
* **helper:** enforce wire compatibility in client ([351d14d](https://github.com/arcboxlabs/arcbox/commit/351d14d90cac5ec504295d6b634e7b3127345751))
* **helper:** harden peer auth and mutation ownership before 1.0.0 ([4baf753](https://github.com/arcboxlabs/arcbox/commit/4baf75378cc053cfe5e658f28f5185a4a64ddad6))
* **helper:** only register authenticated builds ([8a70611](https://github.com/arcboxlabs/arcbox/commit/8a706118932fff1e77ff364bd26f216651e2bbe3))
* **helper:** reject incompatible major helper versions ([32639f5](https://github.com/arcboxlabs/arcbox/commit/32639f5ab2a70c72aa6a729c757b96cd3729acc2))
* **helper:** report version on stdout ([29cd3ea](https://github.com/arcboxlabs/arcbox/commit/29cd3ea8b7239d42154dcb817c2e9d42f8ed9dfb))
* **net:** cap the honored guest window on the inline paths too ([6640822](https://github.com/arcboxlabs/arcbox/commit/6640822ecfeb716f55533cc762ad99f2e4745b46))
* **net:** make TcpBridge uploads lossless and honor the guest window ([d9821ce](https://github.com/arcboxlabs/arcbox/commit/d9821ceedabc6365655c0c5a586a2d6b7c3153b8))
* **net:** reject a guest ACK beyond what the shim sent ([59331fb](https://github.com/arcboxlabs/arcbox/commit/59331fba8f6fbff79751c9856aa9d97ebd8c9707))
* **net:** retransmit lost download frames, wake the idle datapath ([af65e5f](https://github.com/arcboxlabs/arcbox/commit/af65e5ffbe03a65197c731aa81fcb394253b3e2f))


### Code Refactoring

* **helper:** dedupe path ownership and symlink slot logic ([3781642](https://github.com/arcboxlabs/arcbox/commit/37816422bd5d31c2ad0f0880a50aa1492c11da4c))


### Tests

* **e2e:** W13 parallel large downloads + W14 docker build ([c5c0dee](https://github.com/arcboxlabs/arcbox/commit/c5c0deeda644e3ba83f2c752d02a336a819abc2b))
* **helper:** real-binary E2E suite under ARCBOX_HELPER_TEST_ROOT ([b91d413](https://github.com/arcboxlabs/arcbox/commit/b91d4132842a833ec84ac77fb8879e8ac65989ab))


### Documentation

* **e2e:** record the workload-suite findings as resolved ([4961c41](https://github.com/arcboxlabs/arcbox/commit/4961c41ea9e716fa7507eb057f0da108ae88aba2))
* **macos:** refresh stale CLI name and image-version examples ([#459](https://github.com/arcboxlabs/arcbox/issues/459)) ([d6a646a](https://github.com/arcboxlabs/arcbox/commit/d6a646a5cae0c83c79012648264059ab80b81490))
* **net:** align the direct_rx window comment with the 256 KiB cap ([f0a2edc](https://github.com/arcboxlabs/arcbox/commit/f0a2edc51fa1fc4f3fb39b1c3cbc03861776c399))


### Continuous Integration

* **release:** retry crates.io publish through the rate limit ([#455](https://github.com/arcboxlabs/arcbox/issues/455)) ([9b663cc](https://github.com/arcboxlabs/arcbox/commit/9b663ccebea63e185b581901ca7b4f690ab2c000))

## [0.4.24](https://github.com/arcboxlabs/arcbox/compare/v0.4.23...v0.4.24) (2026-07-19)


### Features

* **api:** MachineService.Events lifecycle stream ([76b8b51](https://github.com/arcboxlabs/arcbox/commit/76b8b51b1961b88b0a89568b342216d0f109ff40))


### Bug Fixes

* **api,core:** publish user-machine lifecycle events + address review ([b15c78e](https://github.com/arcboxlabs/arcbox/commit/b15c78e86b111ac3550b7f8b79841d77ff5ef0cf))
* **vmm,agent,daemon:** honor real HVC block capacity; fail loud on shrink ([#453](https://github.com/arcboxlabs/arcbox/issues/453)) ([8de541d](https://github.com/arcboxlabs/arcbox/commit/8de541dcc4ee0140cb9f88992fa77d721d4f452e))


### Tests

* **e2e:** address review — drop non-faithful silent-stall, fix plan ([4283606](https://github.com/arcboxlabs/arcbox/commit/4283606cff09438e972884cfdd5658a7e306c6b9))
* **e2e:** detect log rotation by inode, not length ([f2c6d30](https://github.com/arcboxlabs/arcbox/commit/f2c6d30907ad83e9288b0ad0f490bf9a60cea547))
* **e2e:** lift shared net fixtures and scenario harness ([c72500c](https://github.com/arcboxlabs/arcbox/commit/c72500c03156830e72089df35d60ceb70ff9164d))
* **e2e:** network-fault Phase 1 — bounded-failure regression ([cb4ebf9](https://github.com/arcboxlabs/arcbox/commit/cb4ebf9fcc4e0a6daa5b95ec6b85b6ac55b7dafb))
* **e2e:** network-workload Phase 1 — upload, burst, churn ([170838c](https://github.com/arcboxlabs/arcbox/commit/170838ce04ef64dcdf53ab86cc5f38da1f2e8ec3))
* **e2e:** quiet workload logging, richer diagnostics, record findings ([144bd46](https://github.com/arcboxlabs/arcbox/commit/144bd46dbeb7ddf967fef4b16e4a4f58f3372fba))
* **e2e:** wait for fixture recordings, scan rotated logs ([b95f35b](https://github.com/arcboxlabs/arcbox/commit/b95f35bcce9d3b2c0e6aec8c0902bf1efc9ef655))


### Documentation

* **agent:** refresh memory-pressure PSI comment ([c226e2b](https://github.com/arcboxlabs/arcbox/commit/c226e2b22c9b1e20be355ba2cf467b73a1e75f29))
* **e2e:** network-fault E2E suite plan ([b0fc759](https://github.com/arcboxlabs/arcbox/commit/b0fc759f21cb223c4d1da33dac483bde62613c0d))
* **e2e:** network-workload E2E suite plan ([2c502ff](https://github.com/arcboxlabs/arcbox/commit/2c502ffb3eb90bcf084641efd50e4bbc23feb614))
* **e2e:** record clean-run numbers in the findings section ([242a72a](https://github.com/arcboxlabs/arcbox/commit/242a72aa67a9f2549482e03083e9126734391cc0))


### Continuous Integration

* **codeql:** migrate to advanced setup, Swift buildless ([#449](https://github.com/arcboxlabs/arcbox/issues/449)) ([82f9a97](https://github.com/arcboxlabs/arcbox/commit/82f9a97c58fcd0a998f6cf7336157683ee46c803))


### Miscellaneous Chores

* **assets:** bump boot assets to 0.6.7 (kernel 6.18.38) ([7b1fd59](https://github.com/arcboxlabs/arcbox/commit/7b1fd59faab8d352ba52da9352e4b3ac6deb9ee4))
* **assets:** bump boot assets to 0.6.8 (mkfs.erofs + rootfs razor) ([#448](https://github.com/arcboxlabs/arcbox/issues/448)) ([175ed58](https://github.com/arcboxlabs/arcbox/commit/175ed58b8dcbf067d4e77899f7acc47ffb41d602))
* **assets:** bump boot assets to 0.6.9 ([4304ed4](https://github.com/arcboxlabs/arcbox/commit/4304ed47c739cd00a5cab85bcdfc1b70be0b8c88))
* **assets:** bump boot assets to 0.6.9 (kernel v0.0.20) ([#454](https://github.com/arcboxlabs/arcbox/issues/454)) ([4304ed4](https://github.com/arcboxlabs/arcbox/commit/4304ed47c739cd00a5cab85bcdfc1b70be0b8c88))

## [0.4.23](https://github.com/arcboxlabs/arcbox/compare/v0.4.22...v0.4.23) (2026-07-18)


### Features

* **core,api,agent:** machine boot shim contract — devices, cmdline, machine-init ([#432](https://github.com/arcboxlabs/arcbox/issues/432)) ([4744f96](https://github.com/arcboxlabs/arcbox/commit/4744f960f2751ffba3c3ef8a1c3fce797cb79384))
* **core,api,cli:** machine service correctness — CID, stop semantics, inspect, summary distro ([#436](https://github.com/arcboxlabs/arcbox/issues/436)) ([f1cabc8](https://github.com/arcboxlabs/arcbox/commit/f1cabc8dd79afc7a8ded0ff73ed9933a6999b3e0))
* **core,api:** honor the machine mounts parameter ([#438](https://github.com/arcboxlabs/arcbox/issues/438)) ([e6ff32e](https://github.com/arcboxlabs/arcbox/commit/e6ff32ee542b56a226ef79aaa92640ba31948bc1))
* **core,api:** pull published distro rootfs images for machine create ([#431](https://github.com/arcboxlabs/arcbox/issues/431)) ([2b3fbd3](https://github.com/arcboxlabs/arcbox/commit/2b3fbd385c7ae52490bc7eff02d75bc7be1fd6da))
* **pty,agent,core,api,cli:** interactive machine sessions — PTY primitives crate + bidi ExecSession ([#437](https://github.com/arcboxlabs/arcbox/issues/437)) ([ef94af1](https://github.com/arcboxlabs/arcbox/commit/ef94af184f2022964ff0ab043070b859165b3f2b))


### Tests

* **e2e:** machine lifecycle end to end ([#439](https://github.com/arcboxlabs/arcbox/issues/439)) ([991c077](https://github.com/arcboxlabs/arcbox/commit/991c07773a20e0596fbfa218532ec7e9a5618434))


### Miscellaneous Chores

* **assets:** bump boot assets to 0.6.6 ([#441](https://github.com/arcboxlabs/arcbox/issues/441)) ([709feff](https://github.com/arcboxlabs/arcbox/commit/709fefff8e21b627c14356ba2109d5f54eb105fd))

## [0.4.22](https://github.com/arcboxlabs/arcbox/compare/v0.4.21...v0.4.22) (2026-07-18)


### Features

* **agent,api:** resolve image layer paths via ephemeral containerd views ([6bd7bdc](https://github.com/arcboxlabs/arcbox/commit/6bd7bdc8ede6b18b9825520a4431e1c9f625aa67))
* resolve image layer paths for the Images Files tab (c8d) ([#433](https://github.com/arcboxlabs/arcbox/issues/433)) ([6bd7bdc](https://github.com/arcboxlabs/arcbox/commit/6bd7bdc8ede6b18b9825520a4431e1c9f625aa67))

## [0.4.21](https://github.com/arcboxlabs/arcbox/compare/v0.4.20...v0.4.21) (2026-07-17)


### Features

* **agent:** export the containerd data mount as an NFSv4 child export ([d9879f6](https://github.com/arcboxlabs/arcbox/commit/d9879f623871245e360135a4dd7443a7d7564e0a))
* **agent:** resolve container fs layer paths from containerd snapshots ([1a1f696](https://github.com/arcboxlabs/arcbox/commit/1a1f6964df48351aaaab0beaef657ddfac0e092e))
* **agent:** serve a Finder volume icon at the NFS export root ([65b09f6](https://github.com/arcboxlabs/arcbox/commit/65b09f633dba9b93e2927c38fec43df9254e4a96))
* **api:** SystemService.ResolveContainerFs for filesystem browsers ([1707094](https://github.com/arcboxlabs/arcbox/commit/1707094150496c08b0172c87f6ed72edecdc08c4))
* **daemon:** mount ~/ArcBox from the ArcBox hosts alias when installed ([b42305d](https://github.com/arcboxlabs/arcbox/commit/b42305d24ba53b26be2c2f359f59635b000b8f28))
* **helper:** fixed /etc/hosts alias ops for the ArcBox NFS mount name ([3b56749](https://github.com/arcboxlabs/arcbox/commit/3b567495b2079ac692923fbeeaf12e79b87a171b))
* **vz:** add the ArcBoxVZShim Swift package and its C ABI boundary ([b2e76d8](https://github.com/arcboxlabs/arcbox/commit/b2e76d88a5b20646ae07854ba9318910f471599f))
* **vz:** route build, stop/pause/resume, and device accessors through the shim ([ec420b1](https://github.com/arcboxlabs/arcbox/commit/ec420b10c69b2396bbcb9c1cf45f0b0ffb467395))
* **vz:** route config, boot loaders, and generic platform through the shim ([392c28d](https://github.com/arcboxlabs/arcbox/commit/392c28d353165d9a209a5e120a80a055e6d0849c))
* **vz:** route device configuration constructors through the shim ([9c381be](https://github.com/arcboxlabs/arcbox/commit/9c381be1337d443fb5bacf0d07a183f8f1b11c4f))
* **vz:** route directory shares and VirtioFS through the shim ([23d4192](https://github.com/arcboxlabs/arcbox/commit/23d419299b4d3379095a79c63fd32aece8165c6d))
* **vz:** route macOS identity types and MacPlatform through the shim ([49906db](https://github.com/arcboxlabs/arcbox/commit/49906db05992ced4767f57f7dbfaf6d34186bcef))
* **vz:** route restore images and the IPSW installer through the shim ([1434f33](https://github.com/arcboxlabs/arcbox/commit/1434f3373d25c4b5abb97f1da7bb58015217cde7))
* **vz:** route VM state, start, and request_stop through the shim ([60a418a](https://github.com/arcboxlabs/arcbox/commit/60a418a2d80e3b2ff055152099f631416ce78b4f))
* **vz:** route vsock connect through the shim ([4d22f5e](https://github.com/arcboxlabs/arcbox/commit/4d22f5e02dcea3502c22abb67fe845c7fc92d710))


### Bug Fixes

* **core:** run the agent connect for container fs paths off the async executor ([e3b31eb](https://github.com/arcboxlabs/arcbox/commit/e3b31ebce6cfb139df3d00349fafbe6b2318623f))
* **helper,daemon:** review fixes — append-only tarpc ordinals, alias-before-mount ([688bea9](https://github.com/arcboxlabs/arcbox/commit/688bea99d38bc4845ca694bc00508335a1cfee9e))
* **net:** cap disjoint fragment ranges per reassembly entry at 64 ([943dfa7](https://github.com/arcboxlabs/arcbox/commit/943dfa7d2d81d57169410f6cf4351fe685812136))
* **net:** keep inline flows alive after clean EOF; reap only on error ([49db7ac](https://github.com/arcboxlabs/arcbox/commit/49db7ac614dadb487d65800494f1b7bfe3ef538e))
* **net:** propagate upstream death to the guest as RST on every egress path (ABX-431) ([3359564](https://github.com/arcboxlabs/arcbox/commit/33595640fb48a2bea3b5131ae48386b222ea44e9))
* **vz:** add /usr/lib/swift rpath so the shim's concurrency runtime loads ([f331811](https://github.com/arcboxlabs/arcbox/commit/f331811b4fcc5f139456fbd16914e2798d1e8716))
* **vz:** also rpath doctest links for the shim concurrency runtime ([31511d5](https://github.com/arcboxlabs/arcbox/commit/31511d56ad746e610b7d19da79cd8433bbace7b6))
* **vz:** close the vsock dup'd fd on every connect_blocking abandonment ([ff94d10](https://github.com/arcboxlabs/arcbox/commit/ff94d10fdb41e5bf61684a3a6160de424646ca49))


### Code Refactoring

* **hypervisor:** drop DarwinVcpu's dead VZ state-poll machinery ([5c77cc9](https://github.com/arcboxlabs/arcbox/commit/5c77cc9fdd407ae5c51d94fa5f6ce25d8e1514d8))


### Tests

* **e2e:** container fs resolution + containerd NFS read-through ([914a7b7](https://github.com/arcboxlabs/arcbox/commit/914a7b757d15e900232a5f063113a19fe48e1bd2))


### Documentation

* **net:** align InlineConn.dead doc with error-only semantics; drop stray generated-file churn ([fa84a5e](https://github.com/arcboxlabs/arcbox/commit/fa84a5e010c9e3f9386c02d9bb38ceed5a7cf81f))
* **vz:** correct MacOSInstaller::install param doc (vestigial virtual_machine) ([cae9e75](https://github.com/arcboxlabs/arcbox/commit/cae9e75a7dcd7a2e324d369eaf37efc18167017c))
* **vz:** drop stale ABI-version references after removing the handshake ([54d258d](https://github.com/arcboxlabs/arcbox/commit/54d258d8311398a7a49249ae3923557d533a5e7a))


### Miscellaneous Chores

* **vz:** drop the useless shim ABI-version handshake ([0e40e90](https://github.com/arcboxlabs/arcbox/commit/0e40e90d499dea044058ab1561f73d2de9ae6120))
* **vz:** prune dead code ahead of Swift shim migration ([#413](https://github.com/arcboxlabs/arcbox/issues/413)) ([68f0a6f](https://github.com/arcboxlabs/arcbox/commit/68f0a6f2632b5c63d6781ef5bcfbc4466f9a4e42))
* **vz:** remove the hand-written ObjC runtime interop ([459f41d](https://github.com/arcboxlabs/arcbox/commit/459f41d5228297f76160c1f099b42d60f465cd12))

## [0.4.20](https://github.com/arcboxlabs/arcbox/compare/v0.4.19...v0.4.20) (2026-07-17)


### Features

* **release:** ship vm-agent alongside arcbox-agent ([#426](https://github.com/arcboxlabs/arcbox/issues/426)) ([eadca16](https://github.com/arcboxlabs/arcbox/commit/eadca162285d2f782fc1eafd87d3b115a9211387))
* **sandbox:** fresh-network restore re-addresses the guest (Firecracker 1.16.1) ([#404](https://github.com/arcboxlabs/arcbox/issues/404)) ([fec0b5f](https://github.com/arcboxlabs/arcbox/commit/fec0b5f831257c6922c37de5c918e963b305add8))


### Bug Fixes

* **agent:** reap rpc.mountd and skip zombies in the respawn guard ([#411](https://github.com/arcboxlabs/arcbox/issues/411)) ([1c0ad54](https://github.com/arcboxlabs/arcbox/commit/1c0ad542a53d2fbec0a6d72fc4091446b8de0a46))
* **net:** default the VZ network MTU to 1500 (ABX-423 mitigation) ([b1f2e9c](https://github.com/arcboxlabs/arcbox/commit/b1f2e9c47b4ecfa91a120fcaee47a7c2d0a8c7ea))
* **net:** IPv4-fragment guest-bound UDP datagrams above the link MTU (ABX-428) ([#412](https://github.com/arcboxlabs/arcbox/issues/412)) ([b71bcff](https://github.com/arcboxlabs/arcbox/commit/b71bcff6b70e2910615eaed867dbb4108746b2a4))
* **net:** reassemble guest-originated IPv4 fragments in the classifier (ABX-429) ([#425](https://github.com/arcboxlabs/arcbox/issues/425)) ([feb4fda](https://github.com/arcboxlabs/arcbox/commit/feb4fda9e35c9f402f6fcbbcea0df6851f7e8d4d))


### Code Refactoring

* **daemon:** unify graceful-stop force race into stop_runtime ([#408](https://github.com/arcboxlabs/arcbox/issues/408)) ([539bed9](https://github.com/arcboxlabs/arcbox/commit/539bed9f6f5514e3c2f640aecfc29a5db14cd7d9))


### Documentation

* **net:** reframe NetworkDatapath.mtu doc as buffer sizing ([e44ae1b](https://github.com/arcboxlabs/arcbox/commit/e44ae1baca94dae693484b551b89e4aef925249e))

## [0.4.19](https://github.com/arcboxlabs/arcbox/compare/v0.4.18...v0.4.19) (2026-07-17)


### Features

* **agent:** WatchStats streaming handler with /proc samplers ([1ea321f](https://github.com/arcboxlabs/arcbox/commit/1ea321f30de115d4804db92a5927e424202d86a2))
* **api:** StatsService.Watch server-streaming RPC ([7dfa53d](https://github.com/arcboxlabs/arcbox/commit/7dfa53d2feb7c20fe9c98410b6c6e3ecc93f3463))
* browse guest Docker data at ~/ArcBox (NFSv4 export) ([#399](https://github.com/arcboxlabs/arcbox/issues/399)) ([38887c2](https://github.com/arcboxlabs/arcbox/commit/38887c2cd9e6365a6a406c9693aeb37ab72a450e))
* **cli:** abctl top — live System VM resource monitor ([05cdd4b](https://github.com/arcboxlabs/arcbox/commit/05cdd4b8f508530c585a7e2b8e38590dff5f5bea))
* **core:** StatsHub fans one guest WatchStats stream out to subscribers ([c35379f](https://github.com/arcboxlabs/arcbox/commit/c35379f2632832f72d53aa8cba83344649624942))
* **proto:** WatchStats agent RPC for machine resource samples ([50ea51f](https://github.com/arcboxlabs/arcbox/commit/50ea51f3980298d2c2d36f70343ef1ef76b10bba))
* **stats:** per-container resource stats (ABX-115 P2) ([#398](https://github.com/arcboxlabs/arcbox/issues/398)) ([ab54255](https://github.com/arcboxlabs/arcbox/commit/ab54255513d90c3dd7ebfe88206706f5f01f7972))


### Bug Fixes

* **ci:** discover release PRs via REST list, not search-backed gh pr list ([#401](https://github.com/arcboxlabs/arcbox/issues/401)) ([89dd68e](https://github.com/arcboxlabs/arcbox/commit/89dd68ef2a421b164b463159dbfa7796d650ee08))
* **constants:** gate the ArcboxProfile FromStr impl on std ([9d6429c](https://github.com/arcboxlabs/arcbox/commit/9d6429cd2c07507f89609b7e5f7a049d1240f8d8))
* **daemon:** gate docker.sock self-setup on the profile-default data dir ([#407](https://github.com/arcboxlabs/arcbox/issues/407)) ([b68e912](https://github.com/arcboxlabs/arcbox/commit/b68e912e8a41568e7de1ec8bb9ea6d4bbfa19b6b))
* **docker:** exempt passive observation streams from idle activity ([#396](https://github.com/arcboxlabs/arcbox/issues/396)) ([47d7d1f](https://github.com/arcboxlabs/arcbox/commit/47d7d1fad9719571f78d9cc5d37a6e5dece52580))
* **fleet:** dedup TLS crypto stack on aws-lc-rs (tonic 0.14, russh aws-lc-rs) ([#395](https://github.com/arcboxlabs/arcbox/issues/395)) ([9542819](https://github.com/arcboxlabs/arcbox/commit/9542819448d02e60d1a5c406d4d272ea35ac684d))
* **net:** lossless guest-frame backpressure and direct gateway egress ([#403](https://github.com/arcboxlabs/arcbox/issues/403)) ([71d74c4](https://github.com/arcboxlabs/arcbox/commit/71d74c48f99285bd562bcb29dc39ca21e7af30cb))
* **release:** add crate descriptions to unblock crates.io publish ([#348](https://github.com/arcboxlabs/arcbox/issues/348)) ([08fa700](https://github.com/arcboxlabs/arcbox/commit/08fa7003b0b3b86a3bdab0ef2766e1435487a011))
* **stats:** count only physical NICs; build the agent in stats_watch e2e ([2868394](https://github.com/arcboxlabs/arcbox/commit/28683942e6ad119e09fdfbce415d7ae40740c79f))
* **xtask:** parse moby's post-split docker-vX.Y.Z release tags ([5680c50](https://github.com/arcboxlabs/arcbox/commit/5680c506f944ea3b6525ebf899d6cf368eeede09))


### Tests

* **e2e:** drop the client runtime so pump-stop is observable ([2aa35fc](https://github.com/arcboxlabs/arcbox/commit/2aa35fc6e00b4caa823057a58d7fd78856423d93))
* **e2e:** StatsService.Watch scenario on a real VZ daemon ([0115bff](https://github.com/arcboxlabs/arcbox/commit/0115bffb3f3b60c53ba35ac1b331e8ac9bad2c03))


### Documentation

* **agents:** consolidate the AGENTS.md handbook — audit, gap-fill, complete the index ([#370](https://github.com/arcboxlabs/arcbox/issues/370)) ([0b18787](https://github.com/arcboxlabs/arcbox/commit/0b18787db0fe9a058f4eb647128e90cbb9b6203a))
* **assets:** describe the real tools/boot-bundle version contract ([70a1467](https://github.com/arcboxlabs/arcbox/commit/70a146725955d2c520626474ebc849e4a8e2d42b))
* **e2e:** document the stats_watch scenario ([5e3a6a1](https://github.com/arcboxlabs/arcbox/commit/5e3a6a12789924362733af5e32f531d21a390c7b))


### Miscellaneous Chores

* **agent,e2e:** prep for docker 29.6.1 runtime bundle ([7efd1e9](https://github.com/arcboxlabs/arcbox/commit/7efd1e9bcb3cea2a4148dce3c1f70c0ca8f1cab2))
* **assets:** bump host tools to latest upstream ([bc03dca](https://github.com/arcboxlabs/arcbox/commit/bc03dcae3cec3408ff3164080517baa9cad00a1b))
* **assets:** pin boot bundle 0.6.3 (docker 29.6.1 era) ([20a262b](https://github.com/arcboxlabs/arcbox/commit/20a262b6aee8afe1659fbf687144087ae1534999))
* **master:** release fleet-agent 0.1.1 ([#385](https://github.com/arcboxlabs/arcbox/issues/385)) ([e82fc36](https://github.com/arcboxlabs/arcbox/commit/e82fc361620811d1dcb7f0f85d833c6b9adeb807))
* **master:** release fleet-agent 0.1.2 ([#400](https://github.com/arcboxlabs/arcbox/issues/400)) ([43cb0eb](https://github.com/arcboxlabs/arcbox/commit/43cb0eb5ad76d293510fcc460800fa49954e16ed))

## [0.4.18](https://github.com/arcboxlabs/arcbox/compare/v0.4.17...v0.4.18) (2026-07-15)


### Features

* **api:** cancel a macOS image pull when the client disconnects ([97480f5](https://github.com/arcboxlabs/arcbox/commit/97480f5ca87bafc69bf6f3f5ab96091db714c253))
* **api:** ImageResolve RPC and landed-image summary on ImagePull ([3eab275](https://github.com/arcboxlabs/arcbox/commit/3eab2759630357558547dc9f49c375eafb04b104))
* **api:** route macOS machines + image ops in MachineService (slice 6) ([782a52d](https://github.com/arcboxlabs/arcbox/commit/782a52d98e65d8f9747a72b8ef0c33327794e0c3))
* **api:** serve macOS guests via dedicated MacosService ([ff125d0](https://github.com/arcboxlabs/arcbox/commit/ff125d0b07e40bdc5046944bb274698a46381117))
* **balloon:** free page reporting on the HV backend ([#392](https://github.com/arcboxlabs/arcbox/issues/392)) ([a45bceb](https://github.com/arcboxlabs/arcbox/commit/a45bcebc85b5bb13133e73389ba42f27afdf5f09))
* **ci:** mirror fleet-agent binaries to release CDN ([#389](https://github.com/arcboxlabs/arcbox/issues/389)) ([dae1dc4](https://github.com/arcboxlabs/arcbox/commit/dae1dc46b9c6fec06d8ea471f1c213a93e3076f5))
* **cli:** full macOS guest lifecycle under `arcbox macos` ([29b0f4a](https://github.com/arcboxlabs/arcbox/commit/29b0f4ac586c061f9b4f615545e679cfcad03429))
* **cli:** macOS machine create + macos image commands (slice 6) ([f33f49a](https://github.com/arcboxlabs/arcbox/commit/f33f49a80b3135e9ae412d6f9f307cf389f8e3d0))
* **core:** add macOS base image registry + CoW clone (slice 4) ([daf226c](https://github.com/arcboxlabs/arcbox/commit/daf226c6aa69a2a4cb049aba395efa7bab0aa7df))
* **core:** install macOS base images via the vz installer (slice 4) ([b20e365](https://github.com/arcboxlabs/arcbox/commit/b20e365cbf807618a8df8513fe8b8db1e97088a8))
* **core:** macOS machine lifecycle — boot clones, 2-guest cap (slice 5) ([5f6f51a](https://github.com/arcboxlabs/arcbox/commit/5f6f51a55ed39f0bb0d9f60895bbbe1033e696e7))
* **core:** published macOS image index/manifest schema and locations ([87003b3](https://github.com/arcboxlabs/arcbox/commit/87003b3180897270e6b1374892124b715753907c))
* **core:** record stream/version/os provenance in macOS image metadata ([7c91d1c](https://github.com/arcboxlabs/arcbox/commit/7c91d1c3079432f216e7d34a27c2da1f757b735f))
* **core:** resolve macOS image references without pulling ([5b25bf3](https://github.com/arcboxlabs/arcbox/commit/5b25bf3d99c19b272ff4f08bef0f2abcbef3ef7e))
* **core:** resume pulls mid-stream and clean staging on cancellation ([021d6d0](https://github.com/arcboxlabs/arcbox/commit/021d6d0e02030cbf285cfc353a531cd3709a557d))
* **core:** streaming macOS image pull with sparse zstd restore ([eeb82b5](https://github.com/arcboxlabs/arcbox/commit/eeb82b5b7b789c88db680599123549e18d1b2dae))
* **core:** wire MacMachineManager into Runtime (slice 6) ([08cbf9e](https://github.com/arcboxlabs/arcbox/commit/08cbf9ebc7f90e8b5a0eb106fa876be1cb898763))
* **daemon:** add --no-linux-vm (VM-host-only mode) ([fbd57e8](https://github.com/arcboxlabs/arcbox/commit/fbd57e8e6bb5866cd70eb93000af6df58834bc9e))
* **fleet:** AgentState — push observable agent state to Watch subscribers ([cf4da21](https://github.com/arcboxlabs/arcbox/commit/cf4da215e2102fdf0602e6fc3d2c3fc1bc64843e))
* **fleet:** install-service — user LaunchAgent for start-on-login on macOS ([082a663](https://github.com/arcboxlabs/arcbox/commit/082a663d13a218659057ca4bb885504476c4f79c))
* **fleet:** local gRPC control-plane API on agent.sock (RUN-35 slice 1) ([1b70b37](https://github.com/arcboxlabs/arcbox/commit/1b70b3717ca4f87e3d6c970d1324faf176859868))
* **fleet:** prepare macos_runner_image through the daemon's ImagePull ([192a230](https://github.com/arcboxlabs/arcbox/commit/192a2300bee770c09b546700ce7263f0e47b7e97))
* **fleet:** redesign gateway handshake around agent_version ([8a4e68e](https://github.com/arcboxlabs/arcbox/commit/8a4e68efa75d622985aa72a9502f6abde03a9423))
* **fleet:** scaffold local control-plane proto crate (RUN-35) ([1561507](https://github.com/arcboxlabs/arcbox/commit/15615071871d286e795f8889047ec00c1eb89af0))
* **fleet:** self-update executor and managed binary layout ([73844b3](https://github.com/arcboxlabs/arcbox/commit/73844b35bef529cca5b954aabe2649667ad2e373))
* **fleet:** VmRunner — daemon probe, ephemeral macOS guest lifecycle, ssh exec ([2167dd5](https://github.com/arcboxlabs/arcbox/commit/2167dd5cf7ccf73a2f5f0e5a879fd2b087c3e7e7))
* **macos:** align image pull with schema-2 chunked CDN layout ([6dbb493](https://github.com/arcboxlabs/arcbox/commit/6dbb4939b4f7d09625887e9b8a2c9d9e740f10a4))
* **macos:** attach NAT NIC so guests have working internet ([44a728f](https://github.com/arcboxlabs/arcbox/commit/44a728f4da2f460e7bf6c17e25d90c776ab6fd2a))
* **macos:** download the latest IPSW for image pull ([346f47c](https://github.com/arcboxlabs/arcbox/commit/346f47c3f737b7e22d0fdcd64b56e42c32faf039))
* **macos:** pinned guest MAC, DHCP-lease IP discovery, arcbox macos ip ([ff014d3](https://github.com/arcboxlabs/arcbox/commit/ff014d33f735a29472f395c88957424158b37ada))
* **macos:** point image pulls at darwin.arcboxcdn.com ([9bd84a2](https://github.com/arcboxlabs/arcbox/commit/9bd84a26e42dfae4bad06be7498d6d566ab45d0a))
* **macos:** pull base images by reference with streamed progress ([e366a2d](https://github.com/arcboxlabs/arcbox/commit/e366a2d6877cc99effd90b06a19f492eadc3970f))
* **proto:** add dedicated MacosService for macOS guests ([0078e58](https://github.com/arcboxlabs/arcbox/commit/0078e58c54428bc82ba4599a4a880bbbb409a9cf))
* **proto:** add macOS guest_os + macOS image RPCs to MachineService (slice 6) ([8683558](https://github.com/arcboxlabs/arcbox/commit/868355870521a0b3cbf3a54f2dcad984589fae1e))
* **release:** build fleet agent for Intel macOS ([fb0aa74](https://github.com/arcboxlabs/arcbox/commit/fb0aa74c8fa939eab987c6d1b365e71661f6f670))
* **release:** independent fleet-agent release train ([2e97137](https://github.com/arcboxlabs/arcbox/commit/2e971370c52326da304545cd4c7c8484cb48b45d))
* **vz:** add graceful stop and save/restore to VM lifecycle ([5f4e3a7](https://github.com/arcboxlabs/arcbox/commit/5f4e3a7ae4cff9395964ff6bc66325d72b13568e))
* **vz:** add macOS graphics device configuration ([eaa4f69](https://github.com/arcboxlabs/arcbox/commit/eaa4f6984b6aa651f07f8d9db0d8e942cb9c9bff))
* **vz:** add macOS guest configuration surface ([399d133](https://github.com/arcboxlabs/arcbox/commit/399d1330a3158a616015906b0d96634300dd2efc))
* **vz:** add macOS restore image + Gate A validate example ([8a7e115](https://github.com/arcboxlabs/arcbox/commit/8a7e11599fe4c03562222e4d338cd03d031017c1))
* **vz:** add macos_probe fast config diagnostic ([8e19b19](https://github.com/arcboxlabs/arcbox/commit/8e19b19218dc808751f50d87272eb46ef9abd5df))
* **vz:** add VZMacOSInstaller + Gate B install example ([cd0a305](https://github.com/arcboxlabs/arcbox/commit/cd0a3057fef5826bdb9f72b18248ce34884d0742))
* **vz:** enrich NSError diagnostics for completion errors ([d53bda0](https://github.com/arcboxlabs/arcbox/commit/d53bda0259c823a097dc35965a5ce7341a1543fc))
* **vz:** expose restore image URL + latest-url example ([a8ca25e](https://github.com/arcboxlabs/arcbox/commit/a8ca25e1515e8c914459716d6ecef36fd49a6e10))
* **vz:** macOS install example reaches Gate B ([f2bd911](https://github.com/arcboxlabs/arcbox/commit/f2bd91139ead0972df861f0e7bf282026e38d4b1))


### Bug Fixes

* **ci:** bake musl sha256 into cache key ([758c370](https://github.com/arcboxlabs/arcbox/commit/758c3706c24af11508d87bfa0fb037e8a9e04449))
* **ci:** build portable static fleet-agent with musl-cross on Ubuntu ([241bfef](https://github.com/arcboxlabs/arcbox/commit/241bfefa109577bc3f07e82efffbb77e71e653f1))
* **ci:** pin sha256 of musl-cross toolchain ([c73c9fe](https://github.com/arcboxlabs/arcbox/commit/c73c9fe484aa9aa6d62f8fd4d7e2be5765a46b2a))
* **ci:** vendor musl-cross toolchain to a GitHub Release ([#387](https://github.com/arcboxlabs/arcbox/issues/387)) ([218b8ca](https://github.com/arcboxlabs/arcbox/commit/218b8cad01058c76119607f5f8f8e8dc12f7213c))
* **cli:** make macos image pull name a --name flag ([a9a0ace](https://github.com/arcboxlabs/arcbox/commit/a9a0aceeb9a146efee428321b698ff28d8454fc9))
* **core:** drop redundant test import ([b83ee8c](https://github.com/arcboxlabs/arcbox/commit/b83ee8c47aab40268464e1862a1bee896d362a5b))
* **core:** harden macOS machine lifecycle from code review ([b51692d](https://github.com/arcboxlabs/arcbox/commit/b51692db5d48862119e22b95996cd02b2c9dc6f8))
* **core:** make local-file pulls cancellable ([b919133](https://github.com/arcboxlabs/arcbox/commit/b9191332e45ca179337bfa4d293a40e47b8ba056))
* **fleet:** persist settings before credential in Enroll (RUN-35) ([c867b9a](https://github.com/arcboxlabs/arcbox/commit/c867b9a8e6c064a9b2d627c661479db6602dfc1c))
* **fleet:** send the first heartbeat before waiting on the Attach response ([b4cd6cf](https://github.com/arcboxlabs/arcbox/commit/b4cd6cffee50ec5d3f3cd74840d52de3bce6a7f2))
* **macos:** harden guest lifecycle against traversal and create/pull races ([0c8e09f](https://github.com/arcboxlabs/arcbox/commit/0c8e09fc43faed9a258c50fefd2bb8a8e7c8ea92))
* **macos:** serialize machine lifecycle through runtime slot placeholders ([af6ec8f](https://github.com/arcboxlabs/arcbox/commit/af6ec8ffe18a4a1850bad56beb519de5c1e3333c))
* **macos:** verify each disk chunk before decoding into the image ([fd28afb](https://github.com/arcboxlabs/arcbox/commit/fd28afb7f91747ddc5d9a489efb96ef9d3441250))
* **release:** build the released tag, not the dispatching ref ([1836d60](https://github.com/arcboxlabs/arcbox/commit/1836d606bced7f3dfd6bf6a0e551fb9b5671e71c))
* **release:** iterate all release PRs when refreshing Cargo.lock ([7d83b8d](https://github.com/arcboxlabs/arcbox/commit/7d83b8ddbca36231e4bcbfa4982d815ff52710a2))
* **release:** mark packaged binaries executable in release tarballs ([5cce452](https://github.com/arcboxlabs/arcbox/commit/5cce452f6a44f5e1ebb6f537116a20ad6ec504a6))
* **release:** read gh head branch field ([adca844](https://github.com/arcboxlabs/arcbox/commit/adca844569a93b3659acdbdcb7bece5c9705495f))
* **release:** refresh every open release PR ([eb7155c](https://github.com/arcboxlabs/arcbox/commit/eb7155cff40d7227e839ba3b96f97a417dd9c922))
* **release:** separate release PRs and bootstrap fleet-agent at 0.1.0 ([9ba2ad4](https://github.com/arcboxlabs/arcbox/commit/9ba2ad48650a824b9bcd0b6e1f8054114029802a))
* structural idle-balloon redesign — guest-driven pressure exit + per-request activity ([#390](https://github.com/arcboxlabs/arcbox/issues/390)) ([d101071](https://github.com/arcboxlabs/arcbox/commit/d101071af7e85c477c9fbdd1f1e5fb2c863d0bec))
* **virtio-console:** make PTY allocation thread-safe ([26638b2](https://github.com/arcboxlabs/arcbox/commit/26638b255fc65a7f118b8e63c9930ddbf26523ad))
* **vz:** construct VZMacOSInstaller on the VM's dispatch queue ([66b5707](https://github.com/arcboxlabs/arcbox/commit/66b5707c32d33c9b098305658e18139117972572))
* **vz:** release leaked NSURLs and return promptly on install completion ([a6ef602](https://github.com/arcboxlabs/arcbox/commit/a6ef60220121cd80235afc7f37334ccd27a286a3))
* **vz:** use correct VZMacOSRestoreImage selectors ([0ac38d9](https://github.com/arcboxlabs/arcbox/commit/0ac38d99311eba9c3bc3af937cf28c29fd571a84))


### Code Refactoring

* **macos:** gate IPSW installer behind macos-ipsw-install feature ([17f974e](https://github.com/arcboxlabs/arcbox/commit/17f974e54f95aaea1631b12f19c45457b02360c3))
* remove macOS from MachineService, leaving it Linux-only ([8ad89f1](https://github.com/arcboxlabs/arcbox/commit/8ad89f1158c560430b3aa95ccdcffb2d44446110))


### Tests

* **vz:** add macos_clone_boot diagnostic (verifies CoW clone + boot) ([6759d8a](https://github.com/arcboxlabs/arcbox/commit/6759d8a2835e96cb27c58adfb0151b07adf5fedc))


### Documentation

* **macos:** add macOS guest VM navigation map ([cffbf1c](https://github.com/arcboxlabs/arcbox/commit/cffbf1c27e9117c40a5a88564c0df3c8c0065e4d))
* **macos:** document dedicated MacosService + `arcbox macos` noun ([2034153](https://github.com/arcboxlabs/arcbox/commit/2034153ab3154eff228ac235d7c0aa6308f3c230))
* **macos:** usage, verification status, and zero-trust model (slice 7) ([e1a8060](https://github.com/arcboxlabs/arcbox/commit/e1a8060997ce0ac817f89a46a8f2a4008678e1a9))
* **readme:** rewrite around container runtime positioning ([#351](https://github.com/arcboxlabs/arcbox/issues/351)) ([4e8374d](https://github.com/arcboxlabs/arcbox/commit/4e8374d863d0a88bf1a4dbb151f208283f19e08e))


### Styles

* **daemon:** rustfmt VM-host-only notice ([1b3dd7c](https://github.com/arcboxlabs/arcbox/commit/1b3dd7cfff267f8c5461a11c30de526adb9846b0))


### Continuous Integration

* **fleet:** enforce additive-only control-plane proto with buf breaking ([0637f19](https://github.com/arcboxlabs/arcbox/commit/0637f1923a042ee29f2ed046bec32e74cf1e6d1c))
* **fleet:** move proto breaking check to its own parallel job ([6b23561](https://github.com/arcboxlabs/arcbox/commit/6b235616ef3591c78618b59a73c96fe00bf0b88b))
* limit GITHUB_TOKEN to contents:read ([5fb0ede](https://github.com/arcboxlabs/arcbox/commit/5fb0ede756caeb19f7b135479c5aa9bce4b39814))


### Miscellaneous Chores

* **assets:** bump boot assets to 0.6.2 (kernel v0.0.17, PSI) ([#393](https://github.com/arcboxlabs/arcbox/issues/393)) ([f71df3c](https://github.com/arcboxlabs/arcbox/commit/f71df3c5d183c49cc8486b234508071f1a6d4d8e))
* **master:** release fleet-agent 0.1.0 ([e77f65d](https://github.com/arcboxlabs/arcbox/commit/e77f65da32d628c7adf1d2fd00a9c5daeb147a1c))
* **proto:** regenerate arcbox.v1.rs for ImageResolve ([216b2ff](https://github.com/arcboxlabs/arcbox/commit/216b2ffa19bec337a34d75138759a8258e8674f9))
* **release-please:** drop release-as pin for fleet-agent ([#388](https://github.com/arcboxlabs/arcbox/issues/388)) ([5b83a46](https://github.com/arcboxlabs/arcbox/commit/5b83a464dd5e0cf4c0191ee408f13ac38f8cb4de))
* **release:** reset fleet-agent version train to 0.0.0 ([e21516a](https://github.com/arcboxlabs/arcbox/commit/e21516aaf5bcad1e441f46e3203a833dab6c1a8a))
* update Cargo.lock for release ([f563ddb](https://github.com/arcboxlabs/arcbox/commit/f563ddb1d7e81f1f1be3c2165b90f83e5c589e52))

## [0.4.17](https://github.com/arcboxlabs/arcbox/compare/v0.4.16...v0.4.17) (2026-07-08)


### Features

* **api:** gRPC server reflection + sandbox API reference (CORE-15, CORE-4) ([60f2ca1](https://github.com/arcboxlabs/arcbox/commit/60f2ca1358d1fd4cc3fdc5f4109cb21e0e597f2b))
* **daemon:** seed vm-agent from the app bundle (CORE-5) ([50f5233](https://github.com/arcboxlabs/arcbox/commit/50f5233c97a977ac5410841521de32aece4bd6ac))
* **e2e:** daemon harness with gRPC readiness, signing fixture, and startup failure channel ([#362](https://github.com/arcboxlabs/arcbox/issues/362)) ([49a75fb](https://github.com/arcboxlabs/arcbox/commit/49a75fb915824bf5aea59fdbf0b529519e8a9bb2))
* **fleet:** fall back to local Docker on macOS when ArcBox is unresponsive ([7ec107e](https://github.com/arcboxlabs/arcbox/commit/7ec107eea46098c881b6c5a640b82826b1cd474b))
* **fleet:** hold offer verdicts until the gateway settles them ([5b7b71e](https://github.com/arcboxlabs/arcbox/commit/5b7b71e9581411b8c3626dbd4cb50de26684d19e))
* **fleet:** offer/reject protocol, agent as admission authority ([cb44fae](https://github.com/arcboxlabs/arcbox/commit/cb44faef3661929302bdee2a2725b6272b843e0a))
* **fleet:** port process-group cancel, graceful shutdown, token-file to offer/reject agent ([a63efc7](https://github.com/arcboxlabs/arcbox/commit/a63efc77ce2a108ec7802fe955a3292150661d76))
* **fleet:** resend offer verdicts until the gateway acks ([2e8d376](https://github.com/arcboxlabs/arcbox/commit/2e8d376ba8d572078357af4fac008ccd13b61944))
* **fleet:** store the machine credential in the OS keychain on macOS/Windows ([2390f3d](https://github.com/arcboxlabs/arcbox/commit/2390f3d566b212745ddafb5814171c5660aa3342))
* **hv,e2e:** HV boot root fixes + parallel/dual-backend harness ([#363](https://github.com/arcboxlabs/arcbox/issues/363)) ([634ebc3](https://github.com/arcboxlabs/arcbox/commit/634ebc3862fcb2c0f1cbed43ecc8d7c13a990460))
* **hv:** PL031 RTC, PSCI CPU_OFF, and guest-halt teardown fixes (ABX-416, ABX-403, ABX-415) ([#373](https://github.com/arcboxlabs/arcbox/issues/373)) ([8fda13f](https://github.com/arcboxlabs/arcbox/commit/8fda13f9a7d983865067b18415cbebc3231b5bd1))
* **rpc:** daemon↔agent protocol handshake + buf breaking CI gate (ABX-410) ([#368](https://github.com/arcboxlabs/arcbox/issues/368)) ([b90d236](https://github.com/arcboxlabs/arcbox/commit/b90d2368fb5697e0bf18f1df842381becf0a63f4))
* **sandbox:** expose file I/O through the host chain (CORE-7) ([001c879](https://github.com/arcboxlabs/arcbox/commit/001c87901058d390dab1e385c138c7707240aa1f))
* **sandbox:** expose sandbox ports on the host (CORE-2) ([fb4bbcf](https://github.com/arcboxlabs/arcbox/commit/fb4bbcf239697b7da25ee57ae5e02624aff1404c))
* **sandbox:** fail fast without nested virt + typed agent error codes (CORE-13) ([d5b2152](https://github.com/arcboxlabs/arcbox/commit/d5b2152aac8c11844c9ebccd910a34e73db3d65e))
* **sandbox:** launch the initial cmd after boot (CORE-6) ([fd6e792](https://github.com/arcboxlabs/arcbox/commit/fd6e79209c05374f155be710297219a26510a93e))
* **sandbox:** plumb exec TTY resize end-to-end + honor user (CORE-8) ([d38212e](https://github.com/arcboxlabs/arcbox/commit/d38212e4ca369fa53f12a84f80fdb300d87cbe73))
* **sandbox:** reconcile orphaned resources after agent restart (CORE-14) ([e58a4e1](https://github.com/arcboxlabs/arcbox/commit/e58a4e10027cf03c58b489fe47b8ff29b9c84c3f))


### Bug Fixes

* **agent:** gate docker readiness on API /_ping, not socket-connectable (ABX-408) ([#366](https://github.com/arcboxlabs/arcbox/issues/366)) ([46dcd12](https://github.com/arcboxlabs/arcbox/commit/46dcd12dd9adc79944c57b28cc1b75974ff312d8))
* **agent:** tag sandbox DNAT rules and flush orphans on startup ([2e1fd9d](https://github.com/arcboxlabs/arcbox/commit/2e1fd9def569559c9a754fafadbf811e05b52d59))
* **asset:** unique download temp files + manifest pin in prepare_binaries (ABX-411, ABX-412) ([#369](https://github.com/arcboxlabs/arcbox/issues/369)) ([ddae777](https://github.com/arcboxlabs/arcbox/commit/ddae777959cb8bcfc2082b22b4f89d2f35d1e175))
* **ci:** update vmm-guest-agent bin references + borrow_as_ptr lint ([fa111e8](https://github.com/arcboxlabs/arcbox/commit/fa111e83c314db6ac2fee082c44f33c0aff75629))
* **cli:** serialize daemon spawns — hold a spawn lock across the handoff (ABX-409) ([#367](https://github.com/arcboxlabs/arcbox/issues/367)) ([98ad123](https://github.com/arcboxlabs/arcbox/commit/98ad123fd9b3ca684ba06cf7903a9cec991d0d3a))
* **core:** pick the agent transport from the VM backend, not the fd domain ([878215d](https://github.com/arcboxlabs/arcbox/commit/878215dba79d7d7514c12010e2d3a0f44d219b64))
* **daemon:** arm signal handling for the whole startup window (ABX-407) ([#365](https://github.com/arcboxlabs/arcbox/issues/365)) ([66344e0](https://github.com/arcboxlabs/arcbox/commit/66344e0ee99f81bef81da3a29cafcbf6b9d7277d))
* **example:** update hv_coldboot_once to from_fd_blocking ([795ca02](https://github.com/arcboxlabs/arcbox/commit/795ca028ffc41957b37483927745f7e85795acdb))
* **fleet:** make CredentialStore::new infallible ([0866ea1](https://github.com/arcboxlabs/arcbox/commit/0866ea1c368d943854d2fc0d31b36922ff91149d))
* **fleet:** observe cancellation at every stage and await runner teardown ([0f4015a](https://github.com/arcboxlabs/arcbox/commit/0f4015aa5572914f8e41db5372f4bf82bd762f5f))
* **fleet:** reject non-positive load ceiling at config parse ([989df8b](https://github.com/arcboxlabs/arcbox/commit/989df8b84d4b14aaf2f2f38563f77a50c19bcd1c))
* **fleet:** release in-flight job on runner task panic ([22ed07e](https://github.com/arcboxlabs/arcbox/commit/22ed07e51a1f3e4f43e087b46b43320fdd54d64b))
* **fleet:** require finite load ceiling, scope keychain credential by gateway ([f7c58e1](https://github.com/arcboxlabs/arcbox/commit/f7c58e1726180523240f51db33d534caf8dce0da))
* **fleet:** treat redelivered offers as duplicates until the verdict settles ([3bd37c0](https://github.com/arcboxlabs/arcbox/commit/3bd37c058195270442616c85d970cd37a06b250e))
* **hv:** platform correctness + guest-initiated reboot (ABX-402..405) ([#372](https://github.com/arcboxlabs/arcbox/issues/372)) ([e15f70a](https://github.com/arcboxlabs/arcbox/commit/e15f70ad0c878bf7c29a52d0a0050514b25aa4b6))
* **net:** carry peer MSS into PromotedConn so sinks clamp their own segments ([ba9f0ca](https://github.com/arcboxlabs/arcbox/commit/ba9f0ca76de5b6f577480b55d4d4e563a013a465))
* **net:** clamp host→guest TCP segments to the peer's advertised MSS ([400b3d9](https://github.com/arcboxlabs/arcbox/commit/400b3d941000ed6fe028316f29f77d407d24d26c))
* **net:** keep sub-1460-MSS flows off the GSO/inline inject path ([d435f31](https://github.com/arcboxlabs/arcbox/commit/d435f312bdae95394e5a59e7eca4cc42eb6e1c18))
* **sandbox:** bind exposed ports on loopback + abort truncated file writes ([11008b6](https://github.com/arcboxlabs/arcbox/commit/11008b6d1cfd3c5035a5eb4e5ed228dde4e5c71d))
* **sandbox:** bound streaming channels and stop draining dropped consumers ([4c626b5](https://github.com/arcboxlabs/arcbox/commit/4c626b5e5b77ab58b1beedcb682ea47bc5bd121b))
* **sandbox:** claim the workload slot before dispatching into the guest ([c971bb5](https://github.com/arcboxlabs/arcbox/commit/c971bb5d7384e2be60861e1dba7b7e78a5a4324b))
* **sandbox:** close the create/create id TOCTOU with reserve_id ([1faff10](https://github.com/arcboxlabs/arcbox/commit/1faff10bff96ea857ccca8729298d1fb84f616d5))
* **sandbox:** fail expose when no port could be bound ([9155b7e](https://github.com/arcboxlabs/arcbox/commit/9155b7e3ba7111bb93df2b1d0a926a1d15f56cce))
* **sandbox:** gate create/restore on the orphan sweep + stop the boot-race CoW leak ([cbe7f68](https://github.com/arcboxlabs/arcbox/commit/cbe7f68dfef482b181e2df90d59a645a716200a7))
* **sandbox:** guarantee checkpoint resume + reserve the id before restore ([f21ca1f](https://github.com/arcboxlabs/arcbox/commit/f21ca1fd2d03cda256a8a78cf54d0d4e458ed6e4))
* **sandbox:** guard workload state transitions against a racing stop (pullfrog) ([ebba955](https://github.com/arcboxlabs/arcbox/commit/ebba9558aa924fb32a136342f3c7febb8a50d59f))
* **sandbox:** identity-guard TTL expiry against same-id re-creation ([40bbecc](https://github.com/arcboxlabs/arcbox/commit/40bbeccf7f4bed74262cca64d775d1876ded2fbb))
* **sandbox:** make Stop graceful and release resources on Stopped (CORE-9) ([e543a30](https://github.com/arcboxlabs/arcbox/commit/e543a30eee7e4b2a0b38782bd171728b29a4f4b4))
* **sandbox:** preserve agent error codes (400 for bad input, streaming too) ([ed92284](https://github.com/arcboxlabs/arcbox/commit/ed922844f022deda47caf31e308e19283419037a))
* **sandbox:** reject unimplemented create fields explicitly (CORE-11, CORE-12) ([fbe5136](https://github.com/arcboxlabs/arcbox/commit/fbe5136a0c1159e6185feb1f245de37ff1a07c40))
* **sandbox:** repair asset pipeline — real paths, in-agent rootfs builds (CORE-5) ([c340ddd](https://github.com/arcboxlabs/arcbox/commit/c340dddb1f2bae858e6000eb61ce4403b22b5785))
* **sandbox:** reuse an existing default rootfs when build sources are absent ([913050b](https://github.com/arcboxlabs/arcbox/commit/913050b1fe39e5b61bfe441f16882eb761bc1003))
* **sandbox:** single-flight rootfs builds, sweep tmp, restrict run dir ([f248346](https://github.com/arcboxlabs/arcbox/commit/f2483464144949920baa90e376cf0659c3532f01))
* **sandbox:** tolerate EXDEV when collecting jailer checkpoints ([423ffa8](https://github.com/arcboxlabs/arcbox/commit/423ffa8829cf2fca6ca45065c4727c1098c5a59b))
* **sandbox:** validate ids strictly, fsync EXDEV moves, tolerate record schema drift ([51bf7e9](https://github.com/arcboxlabs/arcbox/commit/51bf7e9ebeea3a201be0648905e68ad2c3a2c944))
* **vm-agent:** drop supplementary groups and kill the whole process group ([d473223](https://github.com/arcboxlabs/arcbox/commit/d4732239a1886ebb5fcc6318fe69c2c826101f4e))
* **vm-agent:** reap orphans, enforce TTY timeout, kill on host disconnect ([222f66f](https://github.com/arcboxlabs/arcbox/commit/222f66f47b7747eb7a0cca6d9e5b81e2cd7c5a19))
* **vz:** dispatch queue-affine VZ calls onto the VM's queue ([#374](https://github.com/arcboxlabs/arcbox/issues/374)) ([8fa80dd](https://github.com/arcboxlabs/arcbox/commit/8fa80dd8b5644d1a5acbd85d44b978b3a4665f4e))
* **vz:** fix MTU override selector detection ([#361](https://github.com/arcboxlabs/arcbox/issues/361)) ([65dc0a0](https://github.com/arcboxlabs/arcbox/commit/65dc0a035f2d434cdf8a69a93b70b61b07809175))
* **vz:** size host-side network socket for enhanced MTU ([#376](https://github.com/arcboxlabs/arcbox/issues/376)) ([0856f4b](https://github.com/arcboxlabs/arcbox/commit/0856f4b6986a5076fa14386485e32f5a9af81454))
* **xtask:** resolve the boot-asset user cache at ~/.arcbox ([57cf9b0](https://github.com/arcboxlabs/arcbox/commit/57cf9b077f8b294d9665f272ca8699b0d0b60fa3))


### Code Refactoring

* **net-inject:** drive RX injection through the unified SplitQueue ([6cb382b](https://github.com/arcboxlabs/arcbox/commit/6cb382b9543ce8c0038bac2eecb9315e0f1f1293))
* **virtio-core:** delete the dead queue_guest module ([360916c](https://github.com/arcboxlabs/arcbox/commit/360916ce081b184fd876e674f592d347078ad9de))
* **vmm:** migrate the legacy net RX worker onto SplitQueue ([c8d1266](https://github.com/arcboxlabs/arcbox/commit/c8d126644bff8f5a3b36f8212287c74909fe210f))


### Tests

* **e2e:** sandbox smoke — full stack over real gRPC (CORE-10) ([0b4c91f](https://github.com/arcboxlabs/arcbox/commit/0b4c91f8ee34f4c278bc7b791296944889bd5918))
* **e2e:** stop origin before restore; clean up agent clippy in sandbox.rs ([78d5872](https://github.com/arcboxlabs/arcbox/commit/78d58727aead99044091a538f803c31ca6ddcff3))


### Documentation

* **agents:** per-directory AGENTS.md rules from the HV campaign ([1098454](https://github.com/arcboxlabs/arcbox/commit/1098454c5889093700e1e6c53224d7fcfb4100d2))


### Styles

* rustfmt the hv_coldboot_once example after from_fd_blocking rename ([f17753a](https://github.com/arcboxlabs/arcbox/commit/f17753ae7cc9d47045176dfd29f1bb43c15aa5e1))


### Miscellaneous Chores

* sync Cargo.lock with merged e2e manifest deps ([5f63cec](https://github.com/arcboxlabs/arcbox/commit/5f63cec8c97654a22184897b9e6d766d6000b336))

## [0.4.16](https://github.com/arcboxlabs/arcbox/compare/v0.4.15...v0.4.16) (2026-07-01)


### Features

* **core:** define VmLifecycle statig HSM (states/superstate/events/effects) ([8f02e34](https://github.com/arcboxlabs/arcbox/commit/8f02e3430919d34ddc1a285c7689c7f267c700af))


### Bug Fixes

* **core:** guard lifecycle actor against stale completions and blocking removal ([4c1c42f](https://github.com/arcboxlabs/arcbox/commit/4c1c42faee8825ed83b7ebafc65c20b20bb21aa1))
* **core:** start persisted machines without recreate after daemon restart ([fddd45c](https://github.com/arcboxlabs/arcbox/commit/fddd45c99e7713501695a119e48ef2b54a46cc53))


### Code Refactoring

* **core:** drive VmLifecycleManager via a statig lifecycle actor ([2c5cc85](https://github.com/arcboxlabs/arcbox/commit/2c5cc85972765d0d7fb78b92330d9a6313b2ec75))


### Miscellaneous Chores

* **core:** add statig(async) state-machine dependency ([c3407f5](https://github.com/arcboxlabs/arcbox/commit/c3407f5798008bdb9a0d7a1d448f021367b6f658))

## [0.4.15](https://github.com/arcboxlabs/arcbox/compare/v0.4.14...v0.4.15) (2026-07-01)


### Features

* **docker:** reconcile host networking against guest container state ([5a9bb29](https://github.com/arcboxlabs/arcbox/commit/5a9bb29e7b205cfa5875c5a9f201d75619ad2a03))
* **docker:** refresh host DNS on network connect/disconnect ([cebd282](https://github.com/arcboxlabs/arcbox/commit/cebd2820734643e20f205aa4ccb6db7c9f34f7b3))
* **fleet:** Docker-based Linux runner support ([4d66d34](https://github.com/arcboxlabs/arcbox/commit/4d66d34a8eca39deafa7ed5da7232af7574c9368))
* **fleet:** verify docker by pulling the runner image at startup ([51557fb](https://github.com/arcboxlabs/arcbox/commit/51557fba291293e4da70cba44ca22b7f611a6902))


### Bug Fixes

* **core,docker:** address adversarial-review findings on the proxy series ([4b57fbf](https://github.com/arcboxlabs/arcbox/commit/4b57fbfb6c1fe2bf4a3b6b2226bff248de5d2650))
* **docker:** harden proxy edge paths ([4df8daf](https://github.com/arcboxlabs/arcbox/commit/4df8daf288cd1738d9bf298a491fbaa28a5bdce9))
* **docker:** only tear down host networking on a terminating kill signal ([b6d3ae9](https://github.com/arcboxlabs/arcbox/commit/b6d3ae9a9910502721175a20959b750a897f8d85))
* **docker:** proxy method-mismatched /containers/{id} instead of 405 ([f7b6e9a](https://github.com/arcboxlabs/arcbox/commit/f7b6e9acc3cdb09fc55b03fa2aa95133eb6e270e))
* **fleet:** admit jobs per capacity pool to match gateway reservation ([3605e14](https://github.com/arcboxlabs/arcbox/commit/3605e14c9f512835b06ee390684896c3016c9f41))
* **fleet:** always route linux jobs through Docker for isolation ([2a5e6b5](https://github.com/arcboxlabs/arcbox/commit/2a5e6b5b5d85f72478c05979fa2c83fa8f81e731))
* **fleet:** connect to ArcBox socket on macOS, fix comments ([33c953d](https://github.com/arcboxlabs/arcbox/commit/33c953d98c45aa0b4567a62fb25740a813d0e406))
* **fleet:** don't probe docker during enrollment ([baff099](https://github.com/arcboxlabs/arcbox/commit/baff099976be02e1dcb23d9819909bb68ac371ba))
* **fleet:** remove orphaned container before reusing its name ([e34be79](https://github.com/arcboxlabs/arcbox/commit/e34be7984f766fcedfa7bf207be1088605c9703a))
* **fleet:** use pullable actions-runner image as default ([e5578c4](https://github.com/arcboxlabs/arcbox/commit/e5578c43878a85a4cde08c9b1c921f08c725124b))


### Performance Improvements

* **core,docker,daemon:** resolve teardown IDs from a host registry ([91620cb](https://github.com/arcboxlabs/arcbox/commit/91620cb9f6fe251e142b6e7a1ce2399c84111f90))


### Code Refactoring

* **docker,daemon:** consolidate guest dockerd queries ([93985d7](https://github.com/arcboxlabs/arcbox/commit/93985d7cf5a0b352bec5cf670d45ca2d4130a316))
* **docker:** classify guest transport errors; gate readiness invalidation ([a683af5](https://github.com/arcboxlabs/arcbox/commit/a683af5516b05f021ce5248a47e8d870900bc098))
* **docker:** move proxy transport state into proxy/state.rs ([f928469](https://github.com/arcboxlabs/arcbox/commit/f9284694c1e426af45fed88f5efae2012f57b3cc))
* **docker:** share the proxy pool with the host reconciler ([5bf19de](https://github.com/arcboxlabs/arcbox/commit/5bf19de5b57dcf0ec6d04cc2ebab3543f04d4d56))
* **fleet:** drop max_concurrent from DockerCapabilities ([7d6fa7b](https://github.com/arcboxlabs/arcbox/commit/7d6fa7bd63213b9ba4a4216497df6438f6c91bbb))
* **fleet:** replace DockerCapabilities with plain arch list ([b877391](https://github.com/arcboxlabs/arcbox/commit/b8773912461516011201a92e36b0884202343f00))


### Tests

* **docker:** handler-path API tests that run in CI ([8c19580](https://github.com/arcboxlabs/arcbox/commit/8c195806cc5121bcc41b0f78c195162e89c4adb4))
* **docker:** mock-guest canned routes for offline handler tests ([c9f41a8](https://github.com/arcboxlabs/arcbox/commit/c9f41a840d7f2e09ee1738094785af934c307fae))
* **docker:** router-level routing coverage that runs in CI ([8600087](https://github.com/arcboxlabs/arcbox/commit/8600087d28c6160cff16c53e38461a1d242ef0c6))


### Styles

* **docker:** rustfmt kill-signal gate tests ([c18648f](https://github.com/arcboxlabs/arcbox/commit/c18648f4a6dc6f758efb0dcbd347706b5aab7b08))

## [0.4.14](https://github.com/arcboxlabs/arcbox/compare/v0.4.13...v0.4.14) (2026-07-01)


### Features

* **core,vmm,docker:** switchable HV/VZ backend for a single System VM ([a7362d2](https://github.com/arcboxlabs/arcbox/commit/a7362d25fee628dbee92faae9ddfcdc80733c739))
* **fleet:** cross-platform runner agent skeleton ([f7e8113](https://github.com/arcboxlabs/arcbox/commit/f7e8113f45e69d19d42398caf2d7ba3ffba7bb4b))
* **fleet:** read enrollment token from file or stdin, not just argv ([8906c39](https://github.com/arcboxlabs/arcbox/commit/8906c3989d12a1bbe207394e9b5317040333b42f))
* **fleet:** stop runners cleanly on SIGTERM/SIGINT ([659d7b4](https://github.com/arcboxlabs/arcbox/commit/659d7b40fdb8e7a2b2a1feddaa2ac1f78940d795))


### Bug Fixes

* **core:** address backend-switch review findings ([a0cd06b](https://github.com/arcboxlabs/arcbox/commit/a0cd06bf5ced854d588cdc454d66559351bb7c56))
* **core:** commit switched backend durably last; correct switch docs ([515ea6b](https://github.com/arcboxlabs/arcbox/commit/515ea6b15331bd976bd0af055d7e811bb78e56d5))
* **core:** ensure System VM is running on a same-backend switch ([8e4789d](https://github.com/arcboxlabs/arcbox/commit/8e4789d0c461a5ae9ef91e1be9ad62311a2af095))
* **docker:** drain guest connection pool on System VM restart ([3243401](https://github.com/arcboxlabs/arcbox/commit/3243401f34de57ee5ed39210c6cae5315fb1e412))
* **docker:** invalidate proxy readiness on System VM restart ([cc72404](https://github.com/arcboxlabs/arcbox/commit/cc724040c1f45c685d024e85b5b4e9f247185674))
* **docker:** reset proxy endpoint via VM incarnation, not an async event ([8b11b45](https://github.com/arcboxlabs/arcbox/commit/8b11b452af8b6f42388e2aca75f33cc2f22fa4c1))
* **fleet:** create credential temp file 0600 from the start ([54a7ef8](https://github.com/arcboxlabs/arcbox/commit/54a7ef8ee01ea27669c1abd9bb84bfadb4c757cf))
* **fleet:** kill the whole runner process group on cancel ([329afd3](https://github.com/arcboxlabs/arcbox/commit/329afd377b57691e9b061cfe848da86ea9274824))
* **fleet:** make ProvisionRunner handling idempotent on job_id ([3196ab6](https://github.com/arcboxlabs/arcbox/commit/3196ab6f359c3ff14745edca5e6683f72d621369))
* **fleet:** persist runner supervisor across attach reconnects ([ef30bee](https://github.com/arcboxlabs/arcbox/commit/ef30beed82480230182922aae58060d08e7c9a35))
* **fleet:** reconnect backoff reset, reject max_concurrent=0, atomic credential write ([9a7c96b](https://github.com/arcboxlabs/arcbox/commit/9a7c96be1f99afca332b4fc5567114b9b7a8d31e))
* **fleet:** refuse insecure credential storage on non-Unix ([add1fdf](https://github.com/arcboxlabs/arcbox/commit/add1fdf70513a6765f6a603f217b089ce2e79273))
* **xtask:** use non-colliding xtask-kit package ([#344](https://github.com/arcboxlabs/arcbox/issues/344)) ([8fb7d35](https://github.com/arcboxlabs/arcbox/commit/8fb7d3547128fd4a83613d3941e6c0f929d25bc7))


### Documentation

* **fleet:** sync vendored proto + correct enroll token help ([4916374](https://github.com/arcboxlabs/arcbox/commit/4916374495e89c6f09ed58c41e2419609287d9b0))


### Styles

* **core,vmm:** apply rustfmt ([ad5b8ca](https://github.com/arcboxlabs/arcbox/commit/ad5b8ca0ccc27ce3ebf9170d5ef52f6f42b6d57f))


### Continuous Integration

* **release:** sync shipped issues to Linear Releases ([#343](https://github.com/arcboxlabs/arcbox/issues/343)) ([4e74a93](https://github.com/arcboxlabs/arcbox/commit/4e74a93dfac25165436ecbab256a87df68d448f2))

## [0.4.13](https://github.com/arcboxlabs/arcbox/compare/v0.4.12...v0.4.13) (2026-06-27)


### Features

* **agent:** run under busybox init as a supervised child ([9f58b19](https://github.com/arcboxlabs/arcbox/commit/9f58b1936f4702e91e96b7a2acd9cd31696afb24))
* **cli:** make 'disk compact' trigger an on-demand trim ([f34657f](https://github.com/arcboxlabs/arcbox/commit/f34657fd25434fb81b74edc8d6f06383afe35de2))
* **profile:** add development runtime profile ([7038d70](https://github.com/arcboxlabs/arcbox/commit/7038d70c694b28916e4aa7b46de218fc5a42dd7c))
* **virtio-blk:** punch holes on DISCARD to reclaim host disk ([a2fa7c5](https://github.com/arcboxlabs/arcbox/commit/a2fa7c55bd101678eec7c0367fd62592b14650de))
* **virtio-blk:** share punch helper, gate DISCARD on writable devices ([9c15a13](https://github.com/arcboxlabs/arcbox/commit/9c15a130b007ac742ae00b5117332bad7edb0201))
* **vmm:** honor WRITE_ZEROES in the HV block worker ([8cdd8ef](https://github.com/arcboxlabs/arcbox/commit/8cdd8ef40c2e573debceba5ae8ae10c43ee87ed4)), closes [#337](https://github.com/arcboxlabs/arcbox/issues/337)
* **vmm:** punch holes on DISCARD in the HV block worker ([fa0c22a](https://github.com/arcboxlabs/arcbox/commit/fa0c22a729a194157e27be74b007cc5040283307))


### Bug Fixes

* **agent:** fail fast when init can't mount the writable layers ([0c90c65](https://github.com/arcboxlabs/arcbox/commit/0c90c6599439d8f9de748c2d4c7e7222db312b4b))
* **api:** surface guest fstrim failures from CompactDisk ([70b0913](https://github.com/arcboxlabs/arcbox/commit/70b091331c01fc8ba7053a2bf532ea907b977256))
* **boot:** gate PL011 earlycon to HV and preserve readiness errors ([c7a902d](https://github.com/arcboxlabs/arcbox/commit/c7a902d336316493118c85185a4d606bcf9dee6e))
* **boot:** pin earlycon to PL011 base so HV early-boot logs are captured ([f4874e8](https://github.com/arcboxlabs/arcbox/commit/f4874e83cd183daf23afc15b68cb7bdf41828cff))
* **boot:** retry guest readiness instead of aborting on transient early-eof ([d614c68](https://github.com/arcboxlabs/arcbox/commit/d614c68667ee76490a1aa9970f9b2cfab129aad3))
* **daemon:** capture guest console output by default ([4ae966b](https://github.com/arcboxlabs/arcbox/commit/4ae966bdca40c1dfd4efd37058bf77c94351a5cb))
* **net:** cache raw DNS responses ([bff8b34](https://github.com/arcboxlabs/arcbox/commit/bff8b34998d3235e2c1e00d976d8b0b7c7774b6a))
* **net:** honor DNS cache hit metadata ([da91b77](https://github.com/arcboxlabs/arcbox/commit/da91b77ec9207ec9520b88f827218aa35101bd5a))
* **net:** widen DNS cache record count sum ([2d88142](https://github.com/arcboxlabs/arcbox/commit/2d88142128a08f20dab58858e9e5ea3248c7d54e))
* **storage:** drop upfront docker.img preallocation, keep image sparse ([#334](https://github.com/arcboxlabs/arcbox/issues/334)) ([5a93974](https://github.com/arcboxlabs/arcbox/commit/5a9397448f7f821db722db9fe41707f64e8f3a22))
* **virtio-blk:** fall back to pwrite when WRITE_ZEROES punch fails ([877d9fa](https://github.com/arcboxlabs/arcbox/commit/877d9facf8d9d94e334328caf910207906726491))
* **virtio-blk:** harden discard range handling ([e95f865](https://github.com/arcboxlabs/arcbox/commit/e95f865de05d2eb808297199ab52ca1ef83604d8))
* **vmm:** preserve block io ordering ([52489da](https://github.com/arcboxlabs/arcbox/commit/52489da1238fe801746bbfc621a59d2185294981))
* **vmm:** preserve block worker capacity after rebase ([f2cc061](https://github.com/arcboxlabs/arcbox/commit/f2cc0613d7511b5172807195d540dd040f8b703b))
* **vsock:** use non-blocking read in remove_closes_fd test ([66b0ffc](https://github.com/arcboxlabs/arcbox/commit/66b0ffc9481ac747e0ab80c1d3cdb83bbad9d2ea))


### Code Refactoring

* **agent:** report fstrim failure via agent error, not text parsing ([10e5ba8](https://github.com/arcboxlabs/arcbox/commit/10e5ba84625fb96afd7fa6556eaee98d3f5f4d2e))
* **blk:** split virtio block device ([282efb5](https://github.com/arcboxlabs/arcbox/commit/282efb51002482189d14f5cb4804c36a8d014ed6))
* **core:** consolidate agent unary rpc ([12c237b](https://github.com/arcboxlabs/arcbox/commit/12c237bdd2d5c536e7a88fc597be1e2ae1b3d5b3))
* **core:** move machine tests out of manager ([110e229](https://github.com/arcboxlabs/arcbox/commit/110e2294d038cfa15bf22feb30b9dc2cee2ac458))
* **core:** split agent client internals ([2436197](https://github.com/arcboxlabs/arcbox/commit/243619798f512c8e86d84000f55895680eeefbb2))
* **core:** split boot asset module ([0dc0c7c](https://github.com/arcboxlabs/arcbox/commit/0dc0c7c6473c5002ba69a51cb7cbe366ba5465f6))
* **core:** split runtime helpers ([566adcc](https://github.com/arcboxlabs/arcbox/commit/566adcc68ae59da076b7ebd88fd97417dcc4eec9))
* **core:** split vm lifecycle types ([6e80f9d](https://github.com/arcboxlabs/arcbox/commit/6e80f9d59159d9eec5ee237da7816752fef7fb93))
* **core:** split vm types and tests ([c5bcbd7](https://github.com/arcboxlabs/arcbox/commit/c5bcbd7e092c4dc48e6af92c2c4161048e5be8de))
* **fs:** split fuse dispatcher ([cfd1ebc](https://github.com/arcboxlabs/arcbox/commit/cfd1ebcf045ab1c4061fed4aa1ab125151aa5fc1))
* **fs:** split passthrough filesystem ([2af0443](https://github.com/arcboxlabs/arcbox/commit/2af0443aa90ce18d74a4ce939bdb0fa692c67dc2))
* **fs:** split virtio fs device ([1cfd756](https://github.com/arcboxlabs/arcbox/commit/1cfd7566e12ea24cf030e220f403956a5a9318cf))
* **hypervisor:** split darwin vm ([9779325](https://github.com/arcboxlabs/arcbox/commit/97793257d7a6588827de383a4593fe2e3e1fb733))
* **hypervisor:** split linux vm ([91f620f](https://github.com/arcboxlabs/arcbox/commit/91f620f6003205346b7164e092b030ba2a00f035))
* **net:** split darwin datapath loop ([e2a5990](https://github.com/arcboxlabs/arcbox/commit/e2a59901c53822626ed3ba8424e3da5b8b092872))
* **net:** split virtio net device ([f5f880e](https://github.com/arcboxlabs/arcbox/commit/f5f880ed71e8721e7bb09c81b79955d7a8ca0871))
* **oci:** split runtime config ([03e81c0](https://github.com/arcboxlabs/arcbox/commit/03e81c0ddafe5c1e118027798d57ee34f810d1a5))
* **packet:** split ethernet helpers ([dae1f03](https://github.com/arcboxlabs/arcbox/commit/dae1f039ea3520492bf44e68cbb838e68de0b631))
* **splicetcp:** split tcp bridge ([6c559ff](https://github.com/arcboxlabs/arcbox/commit/6c559ff2127c874538ed6ad8f40b3b71ce425f7d))
* **vmm:** split darwin hv backend ([0be28c2](https://github.com/arcboxlabs/arcbox/commit/0be28c2006dc622e4a95634aca9b047652100398))
* **vmm:** split device manager ([0416c4b](https://github.com/arcboxlabs/arcbox/commit/0416c4b69bd70319bed2cdf4503b060af0463872))
* **vmm:** split irq chip ([59538d3](https://github.com/arcboxlabs/arcbox/commit/59538d35b0e05639d97b7e137e626ade510cb563))
* **vmm:** split manager core ([585255d](https://github.com/arcboxlabs/arcbox/commit/585255dd27d88133f8ff5b292999cd42b5906ada))
* **vmm:** split snapshot manager ([6648135](https://github.com/arcboxlabs/arcbox/commit/6648135b0ac548b5922043c093dd21ba46979a7f))
* **vm:** split sandbox manager ([d61fed2](https://github.com/arcboxlabs/arcbox/commit/d61fed287b407ba2b66a4a08f3e10a9fd9b071e5))
* **vsock:** split connection manager ([a46ba93](https://github.com/arcboxlabs/arcbox/commit/a46ba93cfc8c2052361e06f8258ac806357cdc00))
* **vsock:** split virtio device internals ([1060d7c](https://github.com/arcboxlabs/arcbox/commit/1060d7c0122039692a5da3779c970463f954c649))
* **xtask:** fully adopt shared xtask utilities ([7e1c545](https://github.com/arcboxlabs/arcbox/commit/7e1c545418c9eb93daa0ea942519fdf02c98da88))
* **xtask:** reuse shared xtask utilities ([b088a11](https://github.com/arcboxlabs/arcbox/commit/b088a11ab3462157eda21f6368a3ace8d24bf9ca))


### Tests

* **hv_e2e:** prove busybox-init agent supervision end-to-end ([1a855e7](https://github.com/arcboxlabs/arcbox/commit/1a855e78c4b7fbd733cc3ec2d033c0a5e0fada1f))
* **vsock:** assert EOF on peer end in remove_closes_fd ([edcbd5a](https://github.com/arcboxlabs/arcbox/commit/edcbd5a9a964b91e41fcf0e344585c0fc0d542d5))


### Styles

* **fs:** format virtio fs device tests ([2c5e63d](https://github.com/arcboxlabs/arcbox/commit/2c5e63d1e936d095f314bbe067de826bad3af32c))
* **vsock:** rustfmt the remove_closes_fd assertion ([99b893d](https://github.com/arcboxlabs/arcbox/commit/99b893d9b265b0a473c4a7f94eed731b10ea1a36))


### Build System

* **rust:** bump workspace toolchain to 1.96 ([a30d30e](https://github.com/arcboxlabs/arcbox/commit/a30d30eda2e5bfa93190b55e9708fbac0b36eeb6))


### Miscellaneous Chores

* **assets:** pin boot assets to 0.6.0 (busybox-init rootfs) ([c5e5ba2](https://github.com/arcboxlabs/arcbox/commit/c5e5ba297f9930aa806bf1e3077bb7ef73bb02ad))
* **assets:** re-pin boot assets to 0.6.1 (rcS init fail-fast) ([703b563](https://github.com/arcboxlabs/arcbox/commit/703b5630734a679957004fcc2f14eab3f894c974))

## [0.4.12](https://github.com/arcboxlabs/arcbox/compare/v0.4.11...v0.4.12) (2026-06-25)


### Bug Fixes

* **daemon:** scan image holders after interrupted VM runs ([fdc38ea](https://github.com/arcboxlabs/arcbox/commit/fdc38eacd1c54cc78378950aa82acb2c7741d25d))
* **docker:** cache guest HTTP readiness in proxy ([#302](https://github.com/arcboxlabs/arcbox/issues/302)) ([80d3318](https://github.com/arcboxlabs/arcbox/commit/80d331832c9be69971cd3b84e56c6791ca8e1690))
* **vmnet:** match vmpktdesc ABI so vmnet_read/vmnet_write stop failing EINVAL ([#303](https://github.com/arcboxlabs/arcbox/issues/303)) ([685bab7](https://github.com/arcboxlabs/arcbox/commit/685bab7c87e92dc9a869073c601c549f87b70f24))


### Performance Improvements

* **boot:** stream guest readiness events ([a49ddeb](https://github.com/arcboxlabs/arcbox/commit/a49ddebbf29e2ebbaf0abd6c55614d49387719eb))
* **core:** tighten boot readiness polling for fast vsock probes ([51d7123](https://github.com/arcboxlabs/arcbox/commit/51d7123e2a72fd55c370ad3f7bd88fad207a5d6e))
* **daemon:** skip docker.img holder scan on clean lock acquisition ([742a788](https://github.com/arcboxlabs/arcbox/commit/742a788302cc93a4a79716644182c7094a92eee4))

## [0.4.11](https://github.com/arcboxlabs/arcbox/compare/v0.4.10...v0.4.11) (2026-06-25)


### Features

* **fakeip:** add DnsResolutionLog clear / remove / len ([7ed5176](https://github.com/arcboxlabs/arcbox/commit/7ed5176c9fa41b32b5d9fde29f294db676d37f51))
* **splicetcp:** support configurable fast-path mtu ([371f4a1](https://github.com/arcboxlabs/arcbox/commit/371f4a19674eea14aa3b6c2cbd449ce58785666b))


### Bug Fixes

* **daemon:** embed Sentry DSN in release builds ([919149d](https://github.com/arcboxlabs/arcbox/commit/919149ddeafbc23dc3710ca0e3d6bf83314cc9b9))
* **daemon:** reconcile vmnet routes after restart ([#330](https://github.com/arcboxlabs/arcbox/issues/330)) ([d617ba3](https://github.com/arcboxlabs/arcbox/commit/d617ba3ceb7839262afc2b19c9fc7ff112de95a0))
* **docker:** address proxy review feedback ([b323595](https://github.com/arcboxlabs/arcbox/commit/b323595da044880b18ce349073862bbf3323d621))
* **fakeip:** use map_or in DnsResolutionLog::len ([531f2cf](https://github.com/arcboxlabs/arcbox/commit/531f2cf26f526e1b64e640800e31238725a33cd2))
* **proxy:** reject unknown guest authorities ([273a401](https://github.com/arcboxlabs/arcbox/commit/273a401ac4cedd5bdd83cf0fab332f089c989c75))


### Performance Improvements

* **proxy:** reuse guest http sessions ([f684680](https://github.com/arcboxlabs/arcbox/commit/f684680e2f1386d24272e6509467ae63ed33570e))


### Code Refactoring

* **context:** move tests out of module ([f56592b](https://github.com/arcboxlabs/arcbox/commit/f56592bd7927feda1fc50d2b4dffa73d64f5f269))
* **context:** split docker context types ([407fa9c](https://github.com/arcboxlabs/arcbox/commit/407fa9cc90afa7b4c290c034de84af86736b8ee1))
* **docker:** centralize proxy pass-through routing ([5c3bb4b](https://github.com/arcboxlabs/arcbox/commit/5c3bb4bcb4fe86d2e34412f3f7c91f7fcbcba5e5))
* **docker:** group api routes by resource ([1be1066](https://github.com/arcboxlabs/arcbox/commit/1be106632e80e0f0377fecf9440bb209ab7ec58a))
* **docker:** group proxy state ([073963c](https://github.com/arcboxlabs/arcbox/commit/073963c92bf77ee1965e95865be2a7b245a90de8))
* **docker:** remove unused api model types ([bc95c7c](https://github.com/arcboxlabs/arcbox/commit/bc95c7c5309e48009786226454abb23b895d5ba9))
* **handlers:** prepare container module split ([728e9d4](https://github.com/arcboxlabs/arcbox/commit/728e9d48519bae02696bd1444097300b4d3df9ce))
* **handlers:** split proxy role helpers ([0bb9913](https://github.com/arcboxlabs/arcbox/commit/0bb9913bd87bd206cbcc8120d6e75e71dea720d8))
* **proxy:** model forward request shapes ([55d56ed](https://github.com/arcboxlabs/arcbox/commit/55d56ed091334b08acd16c8a4ee8cc8204ea9468))
* **proxy:** share vsock stream transport ([e39f265](https://github.com/arcboxlabs/arcbox/commit/e39f26568277a99c8e489109f8cef8e5a10f46e0))
* **proxy:** use hyper client pooling ([338ba48](https://github.com/arcboxlabs/arcbox/commit/338ba48fae14751fdb20b07d6d21d32754cf6fdf))
* **tests:** move e2e runner out of xtask ([d6b5ce3](https://github.com/arcboxlabs/arcbox/commit/d6b5ce3fede02e4a146098ef81ceceb4a1501f21))
* **tests:** split docker api integration suites ([046c797](https://github.com/arcboxlabs/arcbox/commit/046c79756533457e1413623f9367cb324c4e9276))
* **tests:** use standard harness for e2e ([297cf64](https://github.com/arcboxlabs/arcbox/commit/297cf6419fe3868c18c722f452e901d1a1407a23))
* **workload:** split registry internals ([e8cda2e](https://github.com/arcboxlabs/arcbox/commit/e8cda2ec913ecae8d9740be4d675551abb74e5f7))
* **xtask:** migrate boot assets test ([b5b9791](https://github.com/arcboxlabs/arcbox/commit/b5b979171b5b8c2859c6c7e63afa48582b3b29ff))
* **xtask:** migrate repo scripts into xtask ([07e90c4](https://github.com/arcboxlabs/arcbox/commit/07e90c4aee23b3d6e2db5089c1cfddbd1289b04e))


### Documentation

* **docker:** describe proxy architecture ([2aea78c](https://github.com/arcboxlabs/arcbox/commit/2aea78cbc92bdb950f98295c67595c24bce60bcf))
* **docker:** diagram proxy routing ([7210248](https://github.com/arcboxlabs/arcbox/commit/7210248c3e150aac03a2c6de82c85e1641f9896d))


### Continuous Integration

* exclude arcbox-hv from workspace publish ([6c3c5df](https://github.com/arcboxlabs/arcbox/commit/6c3c5dff22fc45e5c8e0c0cb8311e5002fbce546))


### Miscellaneous Chores

* **docker:** add structured proxy tracing ([3e3c0a7](https://github.com/arcboxlabs/arcbox/commit/3e3c0a734a6fdd9ad28acbae297c1987bfe1d4bf))
* **tests:** use tracing in e2e runner ([05be85e](https://github.com/arcboxlabs/arcbox/commit/05be85e316889a6825839569f5768b46b614eef4))

## [0.4.10](https://github.com/arcboxlabs/arcbox/compare/v0.4.9...v0.4.10) (2026-06-19)


### Features

* **splicetcp:** add FlowObserver seam for per-flow byte accounting ([95d0fe8](https://github.com/arcboxlabs/arcbox/commit/95d0fe843c29f4e30e6231829873c37dad2c659f))
* **splicetcp:** add tokio fast-path frame sink ([394670d](https://github.com/arcboxlabs/arcbox/commit/394670d6e54072340608123310ace33c425313f6))


### Bug Fixes

* **splicetcp:** harden tokio frame sink ([cdd5072](https://github.com/arcboxlabs/arcbox/commit/cdd50723fa057b4a7cc44c4fde5a9ec32cfff128))

## [0.4.9](https://github.com/arcboxlabs/arcbox/compare/v0.4.8...v0.4.9) (2026-06-18)


### Continuous Integration

* **release:** publish all workspace crates to crates.io ([#323](https://github.com/arcboxlabs/arcbox/issues/323)) ([94a3263](https://github.com/arcboxlabs/arcbox/commit/94a3263d0e4ba183923757bacda8325441f49817))

## [0.4.8](https://github.com/arcboxlabs/arcbox/compare/v0.4.7...v0.4.8) (2026-06-18)


### Features

* **net:** host-tunnel endpoint — UtunFrameSource/Sink + SOCKS5-aware tcp_bridge + tun_proxy harness ([814bba9](https://github.com/arcboxlabs/arcbox/commit/814bba97545a8634a1ce3df0f5da94bf13e94743))
* **proxy:** SOCKS5 UDP ASSOCIATE client + route guest UDP through it ([e844538](https://github.com/arcboxlabs/arcbox/commit/e8445389681c71bad0333d0b53d5365347ad821d))
* **splicetcp:** parameterize FrameClassifier packet-pool capacity ([#316](https://github.com/arcboxlabs/arcbox/issues/316)) ([ec34f16](https://github.com/arcboxlabs/arcbox/commit/ec34f16da21eea129bb36653062683cdc9d2bca5))
* **tcpstack:** standalone l3_to_l2 for callback-driven (no-fd) ingest ([#313](https://github.com/arcboxlabs/arcbox/issues/313)) ([283716f](https://github.com/arcboxlabs/arcbox/commit/283716f5e0e3617166b92b39c14c1957f875494d))


### Bug Fixes

* **bundle:** drop vm.networking from dev entitlements ([8913c02](https://github.com/arcboxlabs/arcbox/commit/8913c02aff4ac6242dfa277144cb01b3a7ef1103))
* **devenv:** pin apple-sdk_26 so arcbox-daemon links locally ([#305](https://github.com/arcboxlabs/arcbox/issues/305)) ([f43baec](https://github.com/arcboxlabs/arcbox/commit/f43baecbf1406502ad41b52e729328d5d5658d51))
* **net:** correct DarwinTun utun AF-header byte order ([a0ec942](https://github.com/arcboxlabs/arcbox/commit/a0ec942f721fc7f22dc4ded08fde62fa7bbaa733))
* **proxy:** harden SOCKS5 UDP client per review ([dedb863](https://github.com/arcboxlabs/arcbox/commit/dedb8630cbded6e64dcc1bcaf38d4e19fc0f86b2))
* **splicetcp:** apply rustfmt + correct utun AF-header byte-order module doc ([1358fcc](https://github.com/arcboxlabs/arcbox/commit/1358fcc05b08521e235160af3e1d2cccd02ade3a))
* **tcpstack:** proxy IP-literal / domain-less dsts when a system proxy is set ([236fb30](https://github.com/arcboxlabs/arcbox/commit/236fb305da18a2954671841de712970f889b2d0e))
* **tcpstack:** utun AF-header byte order; make tun_proxy functional (Gate C verified) ([88b230a](https://github.com/arcboxlabs/arcbox/commit/88b230a21d474bb46d0cfc4cce7591db8dee44af))


### Code Refactoring

* **net:** extract datapath pool/ring/frame-buf/stats into arcbox-datapath crate ([1f92e3f](https://github.com/arcboxlabs/arcbox/commit/1f92e3f77553d6115abf5dedc98d50f703c04d0e))
* **net:** extract dns_log/proxy_detect into arcbox-fakeip crate ([49c26d3](https://github.com/arcboxlabs/arcbox/commit/49c26d3b6da3af574fce7478679147615ded974e))
* **net:** extract NAT engine into arcbox-conntrack crate (Gate A) ([c9a5465](https://github.com/arcboxlabs/arcbox/commit/c9a5465582f9252c00c18c4d12432dedf5f5678b))
* **net:** extract packet/ethernet/checksum into arcbox-packet crate ([7e70b33](https://github.com/arcboxlabs/arcbox/commit/7e70b3301199e2b6ecfa67dfc0fd2b0089370dc9))
* **net:** extract proxy_tunnel/socket_proxy/inbound_relay into arcbox-proxy crate ([5caa5b5](https://github.com/arcboxlabs/arcbox/commit/5caa5b52c0417889dcf9c2e67cd5ed7309625f20))
* **net:** extract tcp_bridge/classifier/direct_rx into arcbox-tcpstack + FrameSource ingest seam ([b68ffa3](https://github.com/arcboxlabs/arcbox/commit/b68ffa388c0be4766a2b112f8b636908b7079159))
* **net:** rename arcbox-tcpstack crate to splicetcp ([57f0f6d](https://github.com/arcboxlabs/arcbox/commit/57f0f6d5a83249963a0d332b9050c412c176e7c1))
* **net:** sever arcbox-virtio dependency via arcbox-net-virtio crate (Gate B) ([8358bed](https://github.com/arcboxlabs/arcbox/commit/8358bedc949955c735a83789abb64f67c9677147))
* **net:** share utun AF-header framing across endpoints ([e835cdd](https://github.com/arcboxlabs/arcbox/commit/e835cddff434fe9fb646ded2417891d326870ccf))
* **proxy:** split proxy_tunnel + socket_proxy into focused modules ([e2505f4](https://github.com/arcboxlabs/arcbox/commit/e2505f44fd6965b66eec8b54faefd1f7a4899985))
* **tcpstack:** address [#314](https://github.com/arcboxlabs/arcbox/issues/314) review (set_dns_log + Tcp-only EgressConn) ([8836cfc](https://github.com/arcboxlabs/arcbox/commit/8836cfc48682dff7103742fc1f98d136332ed246))
* **tcpstack:** build synthetic Ethernet via arcbox-packet helpers ([b36e429](https://github.com/arcboxlabs/arcbox/commit/b36e429d504beab7fc291513c07f6f8511246cb7))
* **tcpstack:** extract EgressResolver seam from tcp_bridge (behavior-preserving) ([e66723e](https://github.com/arcboxlabs/arcbox/commit/e66723e09937fdd1d99cd13a59f146fc6a6bde5f))


### Tests

* **proxy:** mock SOCKS5 / HTTP-CONNECT round-trips for proxy_tunnel ([0b6739f](https://github.com/arcboxlabs/arcbox/commit/0b6739fa132c2f6df16178d7289d25c1db332bc4))
* small_pool_capacity_classifies_and_falls_back_to_heap. ([ec34f16](https://github.com/arcboxlabs/arcbox/commit/ec34f16da21eea129bb36653062683cdc9d2bca5))


### Continuous Integration

* **release:** publish the library crates to crates.io ([#321](https://github.com/arcboxlabs/arcbox/issues/321)) ([14d73d7](https://github.com/arcboxlabs/arcbox/commit/14d73d78671e85d86aba03f5d5f2488e1c26db44))

## [0.4.7](https://github.com/arcboxlabs/arcbox/compare/v0.4.6...v0.4.7) (2026-06-15)


### Features

* **vmm:** vsock-io worker for event-driven host-to-guest injection ([2c987e1](https://github.com/arcboxlabs/arcbox/commit/2c987e1c8791a2a022220de3146681c15909c73d))
* **vsock:** doorbell hook on host-to-guest RX work in connection manager ([9f6814b](https://github.com/arcboxlabs/arcbox/commit/9f6814b001c4c9c33e922278b619548d64e6af36))


### Bug Fixes

* **core:** raise agent-wait startup timeout to 90s ([#304](https://github.com/arcboxlabs/arcbox/issues/304)) ([1a74b8c](https://github.com/arcboxlabs/arcbox/commit/1a74b8c9285b58ae4a66dc1cd2092f30becec9fa))
* **vmm:** set running before spawning HV worker threads ([e23bdb7](https://github.com/arcboxlabs/arcbox/commit/e23bdb7f3a45986697fbe12c7710948dc5e67034))

## [0.4.6](https://github.com/arcboxlabs/arcbox/compare/v0.4.5...v0.4.6) (2026-06-12)


### Features

* **cli,api:** make --cpus optional, daemon resolves 0 to host core count ([2935a90](https://github.com/arcboxlabs/arcbox/commit/2935a90a495cf787445c7371656cef4587e4e1e8))
* **hypervisor:** add default_vm_cpu_count() helper ([0c14ba1](https://github.com/arcboxlabs/arcbox/commit/0c14ba1bc8d0677a1ccea6ee203b2964f231084f))


### Bug Fixes

* **cli,rpc,hypervisor:** reject --cpus 0, unbake default policy from proto contract ([eaab3a4](https://github.com/arcboxlabs/arcbox/commit/eaab3a446b29a5e10821e05cf728e59c7dc3d4e9))
* **core,api:** resolve cpus=0 through daemon-configured default ([be452b5](https://github.com/arcboxlabs/arcbox/commit/be452b5781d68f3ce9e234b4684db32405ca03f8))
* **daemon,core:** sync route_installed when vm_lifecycle installs the route ([501dfc4](https://github.com/arcboxlabs/arcbox/commit/501dfc48bd04916a4d0ca0ded98062a33312caff))
* **daemon:** enable vmnet bridge NIC by default ([684b045](https://github.com/arcboxlabs/arcbox/commit/684b04581302956c841f5ff4f16bae536156b0e5))
* **daemon:** load config file and env in init_runtime ([aaf4baf](https://github.com/arcboxlabs/arcbox/commit/aaf4baf476cb93feae9a1810b5cd98871037f18c))


### Code Refactoring

* **core:** unify CPU defaults on default_vm_cpu_count() ([b6d30bb](https://github.com/arcboxlabs/arcbox/commit/b6d30bbefd0345cffa875b34382615c78786e6e3))
* **daemon:** consolidate VM config propagation into Runtime::new ([41c5ebe](https://github.com/arcboxlabs/arcbox/commit/41c5ebebadd8e8566789a6f30f02edb4c2b0f942))
* **vmm:** default vCPU counts to host core count ([1db6226](https://github.com/arcboxlabs/arcbox/commit/1db6226b0c1477292eac279ed6c48c30db2cc8dd))

## [0.4.5](https://github.com/arcboxlabs/arcbox/compare/v0.4.4...v0.4.5) (2026-06-10)


### Features

* **core:** own a VM lifecycle per utility VM role ([64fa38d](https://github.com/arcboxlabs/arcbox/commit/64fa38dadcdf0c83f58ac06a24dbe441e326c0ce))
* **core:** role-aware runtime lookups and connector dispatch ([8eb86af](https://github.com/arcboxlabs/arcbox/commit/8eb86afce529c5fbe7808479c80b2b448d9ddf92))
* **daemon,docker:** fan-out resource wait + fail-closed unsupported roles ([03530ca](https://github.com/arcboxlabs/arcbox/commit/03530ca424ce9f46dd82d0d764757543766d5e0d))
* **docker:** add utility VM routing seam ([05aaa9d](https://github.com/arcboxlabs/arcbox/commit/05aaa9d81c4f0978568e4700eabb60987a6e3cfb))
* **docker:** persist workload-to-role bindings for lifecycle routing ([3a7fc34](https://github.com/arcboxlabs/arcbox/commit/3a7fc34faaf5671757e92c60bdcb07683804cbfd))
* **docker:** resolve BuildKit /session role + lazy-recover bindings after daemon restart ([e7a91d6](https://github.com/arcboxlabs/arcbox/commit/e7a91d6f8448a941b8bb71b248ebd36075839d03))
* **docker:** route amd64 runtime to HV/FEX64, fail closed, demote VZ (ABX-375) ([9c85662](https://github.com/arcboxlabs/arcbox/commit/9c8566247d14957f594778ab36568c30ae9d0caa))
* **docker:** schedule Compose projects on a single utility VM role ([588d217](https://github.com/arcboxlabs/arcbox/commit/588d21710ecfb72ebe3e785d4661148dc3fb80d6))
* **net,docker:** fan out host port forwarding per utility VM ([87f27d7](https://github.com/arcboxlabs/arcbox/commit/87f27d712ed9fb5e3a54c0685243af29bb06107c))
* **net:** mount host /private via VirtioFS and rewrite Docker bind paths ([94578ac](https://github.com/arcboxlabs/arcbox/commit/94578ac9d8b5f60407c762cbf1308de29612c6be))
* **vm:** dm-snapshot CoW with jailer mode support ([#208](https://github.com/arcboxlabs/arcbox/issues/208)) ([7e740a1](https://github.com/arcboxlabs/arcbox/commit/7e740a161d851bdfa62e4c214e72a855fee39504))
* **vm:** symlink indirection for dm-snapshot checkpoint/restore ([#209](https://github.com/arcboxlabs/arcbox/issues/209)) ([19dfcbf](https://github.com/arcboxlabs/arcbox/commit/19dfcbffc0165e6b61170d6bffa151619af07db2))


### Bug Fixes

* **core:** check FEX64 at runtime/bin/FEX, matching boot-assets binfmt path ([9efa368](https://github.com/arcboxlabs/arcbox/commit/9efa368f3d367d34ded8ad7f1b95353b00f1f571))
* **core:** eliminate TOCTOU in MachineManager::create by holding write lock ([42f3e3f](https://github.com/arcboxlabs/arcbox/commit/42f3e3fb4b60ffbeeab9233e792f8e1216971b15))
* **daemon:** add ExitTimeOut to launchd plists to prevent SIGKILL during shutdown ([bef9051](https://github.com/arcboxlabs/arcbox/commit/bef90518dcf8baebee1c92142d24190ac58970c5))
* **daemon:** include ExitTimeOut in installed plist ([d423f5a](https://github.com/arcboxlabs/arcbox/commit/d423f5a2f631680a442363b65891168ed6e66694))
* **dhcp:** add expiry for declined IPs to prevent pool exhaustion ([d677941](https://github.com/arcboxlabs/arcbox/commit/d677941c90f9aec8db47c1a34e56f31fc9b38c52))
* **dhcp:** guard lease removal on declined IP and skip quarantine test on low uptime ([526bd71](https://github.com/arcboxlabs/arcbox/commit/526bd71622d32497c894665f359177ec2708a639))
* **dhcp:** only quarantine offered IPs and preserve reservations on release ([de30a8e](https://github.com/arcboxlabs/arcbox/commit/de30a8ee6e09a35317b91994902142c5f2fe63e7))
* **docker:** cfg-gate resolve() to macOS, remove stale Content-Length ([7622347](https://github.com/arcboxlabs/arcbox/commit/7622347c67eecac3cbc774204fe4e9b9888b6da6))
* **docker:** fail closed on ambiguous workload identifiers ([a3fc08c](https://github.com/arcboxlabs/arcbox/commit/a3fc08ceb6990bf338b8b2b0d5a8850aa4b79f9f))
* **docker:** refuse to guess on prefix collisions and keep alias ownership consistent ([937e188](https://github.com/arcboxlabs/arcbox/commit/937e188ae6d2f4192a762b07603613f94767b87f))
* **docker:** track workload aliases and route catch-all by URI role ([2977b3c](https://github.com/arcboxlabs/arcbox/commit/2977b3cdfcf36516d5f317b2fd31afe8a30ee093))
* **docker:** use raw container ID as fallback for networking teardown ([#155](https://github.com/arcboxlabs/arcbox/issues/155)) ([c9bd1a6](https://github.com/arcboxlabs/arcbox/commit/c9bd1a60666606682cb0d221978e0398f6425a9c))
* use virtiofs constants in init.rs, make host_path pub(crate) ([d2350df](https://github.com/arcboxlabs/arcbox/commit/d2350dffd9fdf749d65058bdd840f8056ba1526a))
* **vmm:** disable guest SVE/SME on Apple Silicon (phantom SVE traps) ([7be30d7](https://github.com/arcboxlabs/arcbox/commit/7be30d75d6376f3f6fa3fa44a3d20e2e5b2cab7c))
* **vmm:** mask guest SME so FEX amd64 doesn't SIGILL on Apple SME cores ([8f2c8a7](https://github.com/arcboxlabs/arcbox/commit/8f2c8a7c799038938d8852878f12eb3ba6b805d2))
* **vmm:** recreate default VM when the desired kernel path changes ([82b96a4](https://github.com/arcboxlabs/arcbox/commit/82b96a46c4bf6b51f8eb6b15194ae60fb3254f80))


### Reverts

* **vmm:** drop guest SVE/SME disable (misdiagnosed cause) ([b46b2a6](https://github.com/arcboxlabs/arcbox/commit/b46b2a6d5a40be97564615de4d2ca07a49675520))


### Code Refactoring

* **core:** parameterize VmLifecycleManager on machine name ([36cb538](https://github.com/arcboxlabs/arcbox/commit/36cb5381150c765e1fd65574f0db258ee059785f))
* **core:** pick the hypervisor backend per machine ([77e0952](https://github.com/arcboxlabs/arcbox/commit/77e09527cf72622e8eabdb78643228d159e6cf62))
* **fex:** rename mistaken FEX64 naming to FEX ([f0ddbfb](https://github.com/arcboxlabs/arcbox/commit/f0ddbfb0b179940d7fd60b926a8b5dec03516b9b))
* **vmm:** generalize default-VM drift detection to all overridable fields ([fbde372](https://github.com/arcboxlabs/arcbox/commit/fbde3727f2a35285b646c6ae17fbb2656a81f56e))


### Tests

* **core:** cover MachineManager::create concurrent same-name race ([35d2d23](https://github.com/arcboxlabs/arcbox/commit/35d2d233a290b01c6c5356154e8673a030016164))
* **core:** gate concurrent create tasks on a Barrier ([2686255](https://github.com/arcboxlabs/arcbox/commit/26862550973d15eded6ad9cf9cc125a76df9e465))
* **fex:** add reproducible FEX64 validation harness (ABX-375 step 1) ([158fbce](https://github.com/arcboxlabs/arcbox/commit/158fbceddd4ff3de81d465b19f929ae5743f4626))
* **fex:** classify unprovisioned FEX64 as BLOCKED, not a Gate-A FAIL ([ed3c561](https://github.com/arcboxlabs/arcbox/commit/ed3c5615906b225f14b72035699283972811f26a))
* **fex:** point harness at /arcbox/runtime/bin/FEX; skip B/C when unprovisioned ([0e59700](https://github.com/arcboxlabs/arcbox/commit/0e597008bfb08f31c3433d96fc0e94cf87f5a8b3))


### Documentation

* **docker:** document the BuildKit /session routing limitation ([6c3b2f3](https://github.com/arcboxlabs/arcbox/commit/6c3b2f3bd0ca158a6bb80a9b9e06889c16c76329))
* **docker:** fix stale FEX path in require_amd64_runtime comment ([682d956](https://github.com/arcboxlabs/arcbox/commit/682d956ba1e79865332b6137538b62a955a3bf19))
* **fex:** correct binfmt registration to rootfs /sbin/init, not a guest setup_fex() ([8840336](https://github.com/arcboxlabs/arcbox/commit/8840336bb33883b6eceb413bd0c2209280b84033))
* **fex:** FEX is binfmt-only via a small patch, ships no FEXServer ([dacc25a](https://github.com/arcboxlabs/arcbox/commit/dacc25a88a7a7948dd4e3ef24f90942e9c1caefa))
* **machine:** explain why create holds the write lock across I/O ([8b8ac58](https://github.com/arcboxlabs/arcbox/commit/8b8ac589a129652af7b435d3ae6061613a738a7f))
* **mount:** update mount_standard_shares doc to include /private share ([6e414f7](https://github.com/arcboxlabs/arcbox/commit/6e414f7b595a74d70d9cd5e2c47d068b744d5f25))


### Continuous Integration

* **release:** pass release-please PR JSON via env, not inline interpolation ([#295](https://github.com/arcboxlabs/arcbox/issues/295)) ([d16228a](https://github.com/arcboxlabs/arcbox/commit/d16228a0a1ecaeae18010ce9bfc7140f433b9161))


### Miscellaneous Chores

* **assets:** bump boot assets to 0.5.11 ([45d60e3](https://github.com/arcboxlabs/arcbox/commit/45d60e3f8c8ba2e1d72b76efb6d4a0a6ffd6098c))
* **assets:** bump boot assets to 0.5.13 ([46b45f0](https://github.com/arcboxlabs/arcbox/commit/46b45f0475dc6c2d3960726dc35258d17d4baba2))
* **assets:** bump boot assets to v0.5.10 (working FEX64 runtime) ([89df9a7](https://github.com/arcboxlabs/arcbox/commit/89df9a70ae1fa91ae06cd67c92444e4308edb457))
* **assets:** pin boot assets v0.5.9 with static FEX64 runtime ([7c5c641](https://github.com/arcboxlabs/arcbox/commit/7c5c641695bce70a5390dbf079dbeaa383ebed20))
* **devenv:** add devenv-based reproducible dev shell ([25d3836](https://github.com/arcboxlabs/arcbox/commit/25d383671532fcd76450eadab1ec1cd9442376f3))
* **vmm:** drop redundant clone in drift-detection test ([684ce18](https://github.com/arcboxlabs/arcbox/commit/684ce18a78194751126487a1ba3747a5faae6afe))

## [0.4.4](https://github.com/arcboxlabs/arcbox/compare/v0.4.3...v0.4.4) (2026-05-26)


### Features

* **xnu-net:** add batch datagram I/O crate ([11842bf](https://github.com/arcboxlabs/arcbox/commit/11842bf4100bf36d8ae77467f0c21660a0f60302))


### Bug Fixes

* **xnu-net:** loop until all sent in AsyncBatchDgram::send_batch ([495762d](https://github.com/arcboxlabs/arcbox/commit/495762dd92a58ff0c766ac0c4267b340aa6bc14d))
* **xnu-net:** propagate WouldBlock from BatchDgram and capture errno once ([c60b99f](https://github.com/arcboxlabs/arcbox/commit/c60b99fef5e4d2f3415c891ce1b78f1ae85990ac))


### Performance Improvements

* **xnu-net:** add criterion benchmarks for batch vs single I/O ([caf067c](https://github.com/arcboxlabs/arcbox/commit/caf067ce96639363890bcb2d3adf640a8a752fcc))
* **xnu-net:** interleave bench send/recv, hoist allocations, retry EAGAIN ([4e69855](https://github.com/arcboxlabs/arcbox/commit/4e6985536f3fd1c28aa50a02303377b512a57097))


### Code Refactoring

* **xnu-net:** drop FdWrapper, expose RxEntry from async wrapper, compile async tests by default ([dde99ba](https://github.com/arcboxlabs/arcbox/commit/dde99ba3a43bc8fd9dcb1ef56942c8bdd9cee561))
* **xnu-net:** impl Send for BatchDgram, document MAX_BATCH, test the cap ([60d063c](https://github.com/arcboxlabs/arcbox/commit/60d063c7ef9e0616c02563df4b57c35e10094fe4))


### Tests

* **xnu-net:** add test suite for BatchDgram and AsyncBatchDgram ([e64388d](https://github.com/arcboxlabs/arcbox/commit/e64388d470490ceb35556a904b015c9d517ea70a))


### Documentation

* **xnu-net:** align lib doctest with new recv_batch return type ([1b5e785](https://github.com/arcboxlabs/arcbox/commit/1b5e785b172533577b9dc14f8e967ed995b62b46))


### Miscellaneous Chores

* update Cargo.lock after master merge ([308fe31](https://github.com/arcboxlabs/arcbox/commit/308fe3182003fd61134e429c39f5a352333b9949))

## [0.4.3](https://github.com/arcboxlabs/arcbox/compare/v0.4.2...v0.4.3) (2026-05-26)


### Bug Fixes

* **storage:** increase data disk to 8 TiB and add btrfs auto-resize ([314fe5a](https://github.com/arcboxlabs/arcbox/commit/314fe5ac4f4012896102c2a2187acd3c3b8b92a5))

## [0.4.2](https://github.com/arcboxlabs/arcbox/compare/v0.4.1...v0.4.2) (2026-05-26)


### Bug Fixes

* **agent:** redact docker proxy payload from logs ([e1933b9](https://github.com/arcboxlabs/arcbox/commit/e1933b9f6a350b75ca6e05a720efbf70ce09ee2f))
* **agent:** use is_peer_closed_error for RPC EOF detection ([0b9d446](https://github.com/arcboxlabs/arcbox/commit/0b9d4465c920266a691290bc6e6a5632f2208e36))
* **brew:** drop redundant unprivileged /usr/local/bin link (ABXD-75) ([5c716b0](https://github.com/arcboxlabs/arcbox/commit/5c716b0053b789372aad605ef569fe84f8ff299b))
* **brew:** unlink /usr/local/bin/docker* via helper on brew-uninstall ([acd1229](https://github.com/arcboxlabs/arcbox/commit/acd1229e92bbde868fb1987cbc2e6252c1beb6ad))
* **cli:** consider any plugin binary when assessing setup status ([9e625e1](https://github.com/arcboxlabs/arcbox/commit/9e625e104d8de4f996dc649eb8c305155dbfee4b))
* **cli:** honour DOCKER_CONFIG when locating Docker plugin config ([5ea790a](https://github.com/arcboxlabs/arcbox/commit/5ea790a7773ea19fc61f7feed6058b1d79c8162f))
* **cli:** recognise relative symlink targets in plugin ownership check ([515405e](https://github.com/arcboxlabs/arcbox/commit/515405e8d2ba7e9824e7ea62eaa08d943a224cc9))
* **cli:** surface plugin register/unregister errors in setup output ([6621f74](https://github.com/arcboxlabs/arcbox/commit/6621f7483a88ac740b45322ed244f67673c677ee))
* **cli:** tolerate non-array cliPluginsExtraDirs as foreign state ([331db06](https://github.com/arcboxlabs/arcbox/commit/331db068e998931a0d265d4452c6a9c8744e342d))
* **cli:** write ~/.docker/config.json atomically ([0a51b7b](https://github.com/arcboxlabs/arcbox/commit/0a51b7ba9f32094d563d85db3c9cd12079c0ff14))
* **daemon:** surface total cli_link failure in CliTools::apply ([3367ce9](https://github.com/arcboxlabs/arcbox/commit/3367ce9005e2f5df349a1b11a0fce22a25b0b2c2))
* **release-please:** stop bumping arcbox-hv workspace dep pin ([01835a8](https://github.com/arcboxlabs/arcbox/commit/01835a896cd568e2e007080b773a0578dd6600c0))


### Code Refactoring

* **agent:** extract agent + rpc modules and finish the split ([e571706](https://github.com/arcboxlabs/arcbox/commit/e571706b5289b078ac5784afa440110055c307cf))
* **agent:** extract kubernetes module (k3s lifecycle + RPC) ([b907690](https://github.com/arcboxlabs/arcbox/commit/b907690d3188da23231590aafac57a7076add87e))
* **agent:** extract leaf modules (cmdline/vsock/probe/btrfs) ([52a9b76](https://github.com/arcboxlabs/arcbox/commit/52a9b76981f794b1179208053f3428ec90076ad5))
* **agent:** extract linux/stub mods into separate files ([6215cbd](https://github.com/arcboxlabs/arcbox/commit/6215cbdd2281cc190cbc61f12b7f2e788f0adcf5))
* **agent:** extract proxy / sandbox / system_info modules ([c0cee46](https://github.com/arcboxlabs/arcbox/commit/c0cee46406803c0de0049432b80d07cbd8ff885e))
* **agent:** extract runtime module (containerd + dockerd lifecycle) ([51a7c75](https://github.com/arcboxlabs/arcbox/commit/51a7c75629b5c13be87d79eaf8f452570e647397))
* **net:** extract vmnet bindings into arcbox-vmnet crate ([33be013](https://github.com/arcboxlabs/arcbox/commit/33be013120800d2bc280add2b10faf7651b4a25a))
* **vmnet:** tighten public API and harden error paths ([00d665b](https://github.com/arcboxlabs/arcbox/commit/00d665b5ed8850f3acfecdaa6d8774ab01c155dd))


### Tests

* **vmnet:** add integration test suite for public API ([52d1951](https://github.com/arcboxlabs/arcbox/commit/52d1951090959082dc073566f330f60713965cd7))


### Miscellaneous Chores

* bump `dimicon` and enable `simpleicon` ([#277](https://github.com/arcboxlabs/arcbox/issues/277)) ([a045b52](https://github.com/arcboxlabs/arcbox/commit/a045b52b32e9c3f5d27a58641f18d58484b79871))
* bump `dimicon` to `0.2.0` and enable `simpleicon` ([a045b52](https://github.com/arcboxlabs/arcbox/commit/a045b52b32e9c3f5d27a58641f18d58484b79871))
* **deps:** enable serde_json preserve_order ([ff05fcf](https://github.com/arcboxlabs/arcbox/commit/ff05fcfcaf49360bb6260f9652b73b6ffd553eee))
* **workspace:** promote internal path deps to workspace.dependencies ([cfeffd8](https://github.com/arcboxlabs/arcbox/commit/cfeffd80da6ed26825a9f46096931ea0b5bfa384))

## [0.4.1](https://github.com/arcboxlabs/arcbox/compare/v0.4.0...v0.4.1) (2026-04-24)


### Miscellaneous Chores

* pin pstramp v0.2.0 in assets.lock ([#206](https://github.com/arcboxlabs/arcbox/issues/206)) ([6201014](https://github.com/arcboxlabs/arcbox/commit/620101474b5f99a447f9944ee0f7445cb1103818))

## [0.4.0](https://github.com/arcboxlabs/arcbox/compare/v0.3.21...v0.4.0) (2026-04-24)


### Features

* **agent:** add MmapReadFile RPC to exercise DAX path E2E (ABX-362) ([7f11502](https://github.com/arcboxlabs/arcbox/commit/7f11502b0980e06ca0605eabdc2c9d5341a4751f))
* **bench:** add VirtioFS benchmark suite for M4 performance tracking ([8d893da](https://github.com/arcboxlabs/arcbox/commit/8d893da2e03149646228f0df72bcec4d7b2cf925))
* **cli:** register docker compose/buildx as Docker CLI plugins ([483ab8b](https://github.com/arcboxlabs/arcbox/commit/483ab8b61fb5bd157e10fe62fec06b6795dba15b))
* **constants:** add DOCKER_CLI_PLUGINS constant ([563aeb7](https://github.com/arcboxlabs/arcbox/commit/563aeb728d6a9a176301336c822960c3d97b5b10))
* custom VMM with TSO support via Hypervisor.framework ([#190](https://github.com/arcboxlabs/arcbox/issues/190)) ([0469191](https://github.com/arcboxlabs/arcbox/commit/04691913d910e449ebd47e1249a79d5c96090ca3))
* custom VMM with TSO support via Hypervisor.framework ([#190](https://github.com/arcboxlabs/arcbox/issues/190)) ([c58e6d9](https://github.com/arcboxlabs/arcbox/commit/c58e6d956f14c99c7f9d9b1e6677a258ea6de189))
* **ethernet:** add SYN-ACK and SYN frame builders with option parsing ([6fab71b](https://github.com/arcboxlabs/arcbox/commit/6fab71b4c2b717ea4cc70461618c486a4e50fe40))
* **fs:** VirtioFS DAX support (protocol + window + mapper) ([8864eed](https://github.com/arcboxlabs/arcbox/commit/8864eed668f4c2b19fad422f339c9de7f5b66044))
* **fs:** wire VirtioFS DAX end-to-end ([75e631e](https://github.com/arcboxlabs/arcbox/commit/75e631e1a53750d260f87af6a485589bb98b6b4d))
* **hv:** add arcbox-hv crate with Hypervisor.framework FFI bindings ([#185](https://github.com/arcboxlabs/arcbox/issues/185)) ([b310e89](https://github.com/arcboxlabs/arcbox/commit/b310e8996825a1e01121f3c8685af6b12aff653f))
* **net:** add vmnet bridge NIC (NIC2) to HV backend for container IP routing ([7bebd9a](https://github.com/arcboxlabs/arcbox/commit/7bebd9a8413ab58dd56721513c058e7c9790efa8))
* **net:** crate split + zero-copy RX injection via channel (ABX-352) ([a6edbb8](https://github.com/arcboxlabs/arcbox/commit/a6edbb80e38b58ee6663f1e4bdf13db0fbd7d02b))
* **net:** GSO offload with NEEDS_CSUM for RX injection ([39470db](https://github.com/arcboxlabs/arcbox/commit/39470db5e1f989cc32560a8d7cd665b675b6b642))
* **net:** inline vhost framework + GSO NEEDS_CSUM (10.3 Gbps) ([6075f46](https://github.com/arcboxlabs/arcbox/commit/6075f46c0e1fa0c0ed584fe8e9b1c778304bbd45))
* **sandbox:** support creating sandboxes from Dockerfiles ([#158](https://github.com/arcboxlabs/arcbox/issues/158)) ([23508a3](https://github.com/arcboxlabs/arcbox/commit/23508a35cb3da12a948e28287baa93f15d591854))
* **tcp_bridge:** activate inline inject thread up-front when SEQ is known ([a623714](https://github.com/arcboxlabs/arcbox/commit/a623714f17e2a8751f1998340e8ef73468ee8cd4))
* **tcp_bridge:** add hand-rolled TCP handshake synthesizer ([48e91e1](https://github.com/arcboxlabs/arcbox/commit/48e91e1d97d9a1ca4ce44c1335d42d8dd0978763))
* **virtio-blk:** implement DISCARD + WRITE_ZEROES, delete dead backend ([475e58e](https://github.com/arcboxlabs/arcbox/commit/475e58e5460af9760ac64bd18e8eb0505b2c1788))
* **virtio:** add virtio-balloon device + HV backend wiring (ABX-363) ([d1fc01c](https://github.com/arcboxlabs/arcbox/commit/d1fc01cf70860bdab6a4627ca6b266db5b796ea5))
* **virtio:** connect VirtIO devices to MMIO transport for HV backend (ABX-287) ([bf92a7d](https://github.com/arcboxlabs/arcbox/commit/bf92a7d3a595f280894bf8b0a2ffaa0ce9dd4cf3))
* **virtio:** implement vsock packet processing for HV backend (M2) ([39829a0](https://github.com/arcboxlabs/arcbox/commit/39829a08f4c1ff8e8b0763427cb9fb6c0fe51de3))
* **vmm+agent:** fully enable HVC fast-path block I/O ([4502123](https://github.com/arcboxlabs/arcbox/commit/450212365314f9f3c07d45559713f082a6739e43))
* **vmm:** add DAX mapping counters + per-share stats accessor (ABX-362) ([d0b95b9](https://github.com/arcboxlabs/arcbox/commit/d0b95b92400aced4163934e9947c31dda55342c6))
* **vmm:** add vsock connect_vsock_hv with socketpair + backend dispatch ([b9a6c96](https://github.com/arcboxlabs/arcbox/commit/b9a6c969d91f4dffa8f2d7c26259fa1bc7b55fca))
* **vmm:** async block I/O worker + vsock multi-connection + boot fixes ([9b4dc51](https://github.com/arcboxlabs/arcbox/commit/9b4dc5193c64c575f5432fca894e62585aaa6233))
* **vmm:** dedicated net-io thread for RX injection (ABX-350) ([ed10469](https://github.com/arcboxlabs/arcbox/commit/ed10469bb9168ef8e06226a3037697291657822f))
* **vmm:** deferred vsock OP_REQUEST injection + per-iteration RX poll ([6bf0d4f](https://github.com/arcboxlabs/arcbox/commit/6bf0d4f8d402c8df694c710a88400a195fcda18b))
* **vmm:** enable HV backend in daemon — full boot path through arcbox-daemon ([52a0119](https://github.com/arcboxlabs/arcbox/commit/52a0119956f54a8df176f9b10654a2f99dc0a90d))
* **vmm:** EVENT_IDX notification suppression for net RX (ABX-351) ([5e753c8](https://github.com/arcboxlabs/arcbox/commit/5e753c8d34bade8f649f5ca19ed02232bd45cffe))
* **vmm:** HVC fast-path block read handler ([7f65535](https://github.com/arcboxlabs/arcbox/commit/7f655359732d7177e8bc740dcabb16a5d02dbd5a))
* **vmm:** implement HV backend boot path and dual-backend switching (ABX-286, ABX-288) ([f89d865](https://github.com/arcboxlabs/arcbox/commit/f89d86564d33b96705912e727ad6eea9ea3977ea))
* **vmm:** implement PSCI CPU_ON secondary vCPU spawning and WFI blocking (M3) ([0e983a8](https://github.com/arcboxlabs/arcbox/commit/0e983a8b51c8d93c9f8ac1a8a0791bae632f14cb))
* **vmm:** rewrite HV boot path to use rust-vmm crates (vm-memory, linux-loader, vm-fdt) ([402bad2](https://github.com/arcboxlabs/arcbox/commit/402bad29b219aeb7b5f705668443c959c4fc2232))
* **vmm:** switch E2E test to production boot path (rootfs.erofs block device) ([14211a4](https://github.com/arcboxlabs/arcbox/commit/14211a440b933375a7272e22cf0f6344fa3ce5d2))
* **vmm:** VirtIO console TX processing + console=hvc0 — init output visible ([cde2abd](https://github.com/arcboxlabs/arcbox/commit/cde2abd51480cd16bd78d1703b8a1363b3cfb151))
* **vmm:** VirtIO-blk multi-queue + DNS fix + flush barrier ([6d26d38](https://github.com/arcboxlabs/arcbox/commit/6d26d38677777fcbb4e4caa7cf97ccb2be1f9451))
* **vmm:** vsock data forwarding infrastructure (TX direction) ([0045246](https://github.com/arcboxlabs/arcbox/commit/004524632c214e34befde03eeb464bf2468ec0cf))
* **vmm:** vsock RX injection via poll_vsock_rx in WFI handler ([821c73c](https://github.com/arcboxlabs/arcbox/commit/821c73cde2e41cdf89e00d8f92fac986de7de8ba))
* **vmm:** vsock TX queue polling + connection state tracking ([4e4aa95](https://github.com/arcboxlabs/arcbox/commit/4e4aa9556b718ede46a5570f8c461b75c4a7088c))
* **vmm:** wire VirtIO device instances into HV backend for guest I/O [M1] ([85d4ae4](https://github.com/arcboxlabs/arcbox/commit/85d4ae4592e441080153d9b6d1998874cc1b25b0))
* **vsock:** port vhost-device-vsock connection state machine ([5afe8fc](https://github.com/arcboxlabs/arcbox/commit/5afe8fcdb6ff03732297101744ee6f5e8d87f7af))


### Bug Fixes

* **agent,cli:** address PR [#267](https://github.com/arcboxlabs/arcbox/issues/267) review comments ([7aac968](https://github.com/arcboxlabs/arcbox/commit/7aac9686868cae81b5eae853363fb8348b8cc688))
* **agent:** cast FS_IOC_* constants to libc::Ioctl for target portability ([a1294fd](https://github.com/arcboxlabs/arcbox/commit/a1294fdaff88c9cbd70b29f30631edd27dda7dae))
* **agent:** make ensure_runtime non-blocking to avoid daemon RPC timeout ([f606369](https://github.com/arcboxlabs/arcbox/commit/f6063695249c6d1bb54b9fb63d198b1da2c1db17))
* **agent:** mount arcbox-dax under /run, drop rejected cache= option ([123b35d](https://github.com/arcboxlabs/arcbox/commit/123b35d2926f59cc97c0609e611d5e605284c707))
* **fs:** per-VirtioFS DAX window allocation ([458a242](https://github.com/arcboxlabs/arcbox/commit/458a242dec956c34b8a786bc25f5397cfda7e15c))
* **fs:** VirtioFS DAX end-to-end working ([9cb08fd](https://github.com/arcboxlabs/arcbox/commit/9cb08fd5e221c8122e67e20b426156e1f36da8cc))
* **guest:** bound thread spawns and reduce stack size in vm-agent ([34abc8a](https://github.com/arcboxlabs/arcbox/commit/34abc8a97c454c5bd49d918727f5b771581ddbc2))
* **hv:** add exit_all_vcpus wrapper, fix GIC state memory leak, export register constants ([758cb36](https://github.com/arcboxlabs/arcbox/commit/758cb365333a9d2f87572e8a7b98f6a1a8a4357d))
* **hv:** clamp vsock fd dup target below RLIMIT_NOFILE ([4cf3ec2](https://github.com/arcboxlabs/arcbox/commit/4cf3ec275be799dec2bb7d0d8cca361115381d79))
* **hv:** join net RX worker on shutdown + release fence on avail_event ([78da37b](https://github.com/arcboxlabs/arcbox/commit/78da37b89f615ffa18bd72c206fc9eece7a89efa))
* **hv:** pass vCPU IDs to hv_vcpus_exit on arm64 (ABX-367 root cause) ([4a48d2a](https://github.com/arcboxlabs/arcbox/commit/4a48d2a85c701ebaa9009bdb5733ab862003de57))
* **hv:** re-export check, typed ignore reasons, safer GIC test drop ([99a8b69](https://github.com/arcboxlabs/arcbox/commit/99a8b69af5ae76f1ab4c6db1bb9e023f89efeebe))
* **hv:** update GIC API for Xcode 26 SDK and fix RAM base address layout ([cbf4fd4](https://github.com/arcboxlabs/arcbox/commit/cbf4fd41830f9fb2e8ad9974757f0f69ddbfb6d2))
* **net-inject:** advertise TCPV4 GSO for oversized inline frames ([dab689f](https://github.com/arcboxlabs/arcbox/commit/dab689f88973334b7ddc2b49864aece700225ee4))
* **net-inject:** drop GSO for RX-injected fast-path frames ([75b1230](https://github.com/arcboxlabs/arcbox/commit/75b123023e4b01ad6e6851c4a44d47383dc7c244))
* **net-inject:** relay FIN+ACK to guest on host EOF ([6cfb69d](https://github.com/arcboxlabs/arcbox/commit/6cfb69d4f54c38ef578109585c8efcfffd9db734))
* **net,vmm:** address AI code-review comments on PR [#259](https://github.com/arcboxlabs/arcbox/issues/259) ([4923d27](https://github.com/arcboxlabs/arcbox/commit/4923d270c8ef77269c970e0ceeca3d6f9cd6dbb9))
* **net,vmm:** resolve P0 release blockers from code review ([ef95419](https://github.com/arcboxlabs/arcbox/commit/ef95419ae4250c4831dec75f02da1366272e826f))
* **net:** address AI code-review comments on PR [#260](https://github.com/arcboxlabs/arcbox/issues/260) ([c2246f8](https://github.com/arcboxlabs/arcbox/commit/c2246f88f61c8c7e7553e29335351da0127cf700))
* **net:** complete hot-path log level downgrade (ABX-324) ([597dc2e](https://github.com/arcboxlabs/arcbox/commit/597dc2ed58170fbba6bd1eea8d2ae3b1fe4e25ef))
* **net:** defer inline fast-path promotion until SEQ/ACK sync ([d4cdf9f](https://github.com/arcboxlabs/arcbox/commit/d4cdf9fcad7833eb2eded84e21ca7e9cf64fe5df))
* **net:** fix fast-path promotion panic, EMSGSIZE, and workspace clippy errors ([52e7233](https://github.com/arcboxlabs/arcbox/commit/52e72330cab4b922186dd1dd38b1544e28769c2b))
* **net:** route fake-IP TCP connections through proxy before domain lookup ([0f3c6d4](https://github.com/arcboxlabs/arcbox/commit/0f3c6d49c38403b5681de63dd7933746e43d6914))
* **net:** share our_seq atomic between inject thread and intercept ACKs ([6dba9d0](https://github.com/arcboxlabs/arcbox/commit/6dba9d0121aa81d4edb32d44b8377e57f1c2bda4))
* **net:** skip retransmits and drain on Broken pipe in fast-path TX ([5315647](https://github.com/arcboxlabs/arcbox/commit/53156474d6b18ce987dc7b9433a79f2d83844081))
* **net:** use device ID for primary NIC lookup instead of HashMap scan ([ddbb49a](https://github.com/arcboxlabs/arcbox/commit/ddbb49a3d403d0f2d740dc12cbae8e266d60b131))
* **net:** use device ID for primary NIC lookup instead of HashMap scan ([056b14e](https://github.com/arcboxlabs/arcbox/commit/056b14eae0f8e328f8b807f7a93cf02f9b0233de))
* **net:** use full TCP checksum for fast-path frames under MTU ([287f272](https://github.com/arcboxlabs/arcbox/commit/287f272d1efd32ddfd57295a6257304574e325b8))
* **transport:** blocking vsock transport for HV agent control plane ([198e2e7](https://github.com/arcboxlabs/arcbox/commit/198e2e7a6785093b043fb290b2ae9d3a3f862bbe))
* **transport:** clean up blocking transport warnings, add block_in_place ([853cbc3](https://github.com/arcboxlabs/arcbox/commit/853cbc344bd7800c07a6212faa70294634250c3c))
* **transport:** use tokio::net::UnixStream for HV socketpair connections ([069b226](https://github.com/arcboxlabs/arcbox/commit/069b2266861a863d62c02dd833823db41ed16a91))
* **virtio-core:** cap descriptor-chain iteration at queue size ([0a43be1](https://github.com/arcboxlabs/arcbox/commit/0a43be17ceb0e9e8acfeca5eec0f3a9dadaed0f4))
* **virtio-fs:** exercise DAX fast path end-to-end on HV (ABX-366) ([33341ba](https://github.com/arcboxlabs/arcbox/commit/33341bad4f73d8a34ca5308390e5a2b9f7eec71e))
* **virtio-fs:** FUSE 7.36+ DAX layout, TOCTOU-safe inode open ([6bc9f03](https://github.com/arcboxlabs/arcbox/commit/6bc9f030203c72cf5fcfab339c6342aa9a801d28))
* **virtio-net:** configure TAP offload after feature negotiation ([9164bef](https://github.com/arcboxlabs/arcbox/commit/9164befb17c93e0aa80ef41c3561a7117401c12b))
* **virtio-net:** implement MRG_RXBUF multi-chain RX delivery ([cb707cd](https://github.com/arcboxlabs/arcbox/commit/cb707cd2098c61d7d0006efde66d63e996006fc4))
* **virtio-net:** retry-on-ENOBUFS in guest TX write path ([b9f69aa](https://github.com/arcboxlabs/arcbox/commit/b9f69aadfb263fadaceb0c081dc86d56ab9a3dee))
* **virtio-rng:** drop zero-fill fallback on getrandom failure ([7ce3dfd](https://github.com/arcboxlabs/arcbox/commit/7ce3dfd2e5caba8c213c61bf0edbb3822068b468))
* **virtio-vsock:** handle OP_SHUTDOWN half-close flags per spec ([ea41173](https://github.com/arcboxlabs/arcbox/commit/ea41173bffdb8fd065969722bc560039e73f56d0))
* **virtio-vsock:** lower credit-update threshold 48 KB → 4 KB ([98a591d](https://github.com/arcboxlabs/arcbox/commit/98a591ddc1f783512d367b2fc08fdb58ef86fea7))
* **virtio-vsock:** proactive CREDIT_REQUEST at half-window ([e00e97d](https://github.com/arcboxlabs/arcbox/commit/e00e97d4157aec2e6d9e38b9a847aa9add6d69aa))
* **virtio-vsock:** retry partial writes + bump socketpair SO_SNDBUF (ABX-365) ([683d616](https://github.com/arcboxlabs/arcbox/commit/683d6161cf261138378fb308d8591dc46d7e6c39))
* **virtio:** add VIRTIO_F_VERSION_1 to vsock and fs devices ([fb831d8](https://github.com/arcboxlabs/arcbox/commit/fb831d8e2a161052d7219a7a49e7b96683b9a9a4))
* **virtio:** address P2 review findings — u16 wrapping, EVENT_IDX, backend ([e30ce9c](https://github.com/arcboxlabs/arcbox/commit/e30ce9c617618ffa3ee8b7e2cfa54e42fa73cdaf))
* **virtio:** rewrite VirtioFs process_queue to read from guest memory ([35f78fc](https://github.com/arcboxlabs/arcbox/commit/35f78fc888498572ae3f80d22e3c4f8386196bb0))
* **virtio:** set avail_event in used ring for EVENT_IDX notification ([3766428](https://github.com/arcboxlabs/arcbox/commit/3766428a3e336a6445fc79d99a4bf06982000f2c))
* **vm-agent:** replace map().unwrap_or() with map_or() on Result ([8651caf](https://github.com/arcboxlabs/arcbox/commit/8651caf6537296984f53e77d542c8802349c5264))
* **vmm:** address P0/P1 review findings — overflow, flush ordering, DAX, GSO ([106a6ca](https://github.com/arcboxlabs/arcbox/commit/106a6ca968667a7729b6442477dd466507cb462c))
* **vmm:** advance PC on unhandled sysreg traps so Linux boot progresses ([f2cf0cf](https://github.com/arcboxlabs/arcbox/commit/f2cf0cfd950c2821ad815955d8e1baa21fe333d3))
* **vmm:** attach FsServer handler to VirtioFS device for FUSE processing ([12cfb16](https://github.com/arcboxlabs/arcbox/commit/12cfb16e4a8ea9af4531cf6b656f652770afc4a5))
* **vmm:** bounded-time Vmm::stop() on HV via cancel+unpark loop (ABX-367) ([eed7ff0](https://github.com/arcboxlabs/arcbox/commit/eed7ff0f0e4f6d0172c392fe93a53d8dd5b1251f))
* **vmm:** complete virtio-net checksum offload in HV TX path ([cfed9fe](https://github.com/arcboxlabs/arcbox/commit/cfed9fed42d409e6b689b7fab4881d6e7f3b9c21))
* **vmm:** correct GIC SPI INTID numbering in FDT + add write barrier ([18270c5](https://github.com/arcboxlabs/arcbox/commit/18270c5eb1e098338e901c281094606c1aa18617))
* **vmm:** DAX TOCTOU race + checked_sub for all GPA translations ([1d7786b](https://github.com/arcboxlabs/arcbox/commit/1d7786b9268a8b9c49a8d42441203e138672a279))
* **vmm:** dispatch pause/resume/snapshot on backend (ABX-360) ([4706b9e](https://github.com/arcboxlabs/arcbox/commit/4706b9ed2abfd5d0762f823ffabf2c9093c5ca68))
* **vmm:** eliminate memory safety UB and harden DAX mapper ([8cf4c68](https://github.com/arcboxlabs/arcbox/commit/8cf4c68dd78a35fa97abfbdeb1181d907d44704b))
* **vmm:** enable `gic` feature by default ([d16bcb5](https://github.com/arcboxlabs/arcbox/commit/d16bcb554965d81a514f8f94085fd488a7b3cd01))
* **vmm:** fix GPA-to-offset translation for VirtQueue memory access ([e4bad37](https://github.com/arcboxlabs/arcbox/commit/e4bad378f19182e9cefd4e2f70fab7b023c47c90))
* **vmm:** harden VirtIO queue index wrapping, DAX lifecycle, and error checking ([ecfb773](https://github.com/arcboxlabs/arcbox/commit/ecfb77307939e58e8268a09314ee7cec6b2da510))
* **vmm:** HV Drop order, DAX drain, vCPU registry sequencing ([f2ea4f6](https://github.com/arcboxlabs/arcbox/commit/f2ea4f661c355358e4ce4596ec6e9570c4596e7f))
* **vmm:** Phase 3 — fix VirtIO MMIO address, initrd placement, reach /init ([423688a](https://github.com/arcboxlabs/arcbox/commit/423688ad876837d44ce2a32566dcc1505c7657b8))
* **vmm:** remove double PC advance on HVC exit ([9e9d44b](https://github.com/arcboxlabs/arcbox/commit/9e9d44b83dd172459209c06dc6ee53b5ccf52770))
* **vmm:** replace cast suppress with try_from for vsock host_port → RawFd ([20c625b](https://github.com/arcboxlabs/arcbox/commit/20c625b116d8bc4d444fb934ee6200687d5dc16e))
* **vmm:** single OP_REQUEST injection per port, remove debug noise ([9056346](https://github.com/arcboxlabs/arcbox/commit/905634658e168665fba5674ce44f2961fb902ef2))
* **vmm:** size peer-side SO_RCVBUF on HV network socketpairs ([55763d7](https://github.com/arcboxlabs/arcbox/commit/55763d79062534c50b531b0d9aa3e2deab75918c))
* **vmm:** stop_darwin_hv drops worker senders so joins return (ABX-364) ([97b8048](https://github.com/arcboxlabs/arcbox/commit/97b8048657a786bea437260bfbfa961704c3ddb5))
* **vmm:** trigger IRQ after vsock OP_REQUEST injection + ephemeral src_port ([d71ceb0](https://github.com/arcboxlabs/arcbox/commit/d71ceb03ac65a6a3bdea2adffbfb492db0dccfba))
* **vmm:** vsock OP_REQUEST injection + IOMMU/DMA address analysis ([1d66cff](https://github.com/arcboxlabs/arcbox/commit/1d66cffd7ed4e37fe0dc5cd84f773eba139893bf))
* **vmm:** XZR register handling + IRQ GSI mapping for ARM64 ([279fdc0](https://github.com/arcboxlabs/arcbox/commit/279fdc067220b7654c52e36ef59aceee38486073))
* **vmnet:** use XPC dictionary instead of CFDictionary for vmnet_start_interface ([7dfb785](https://github.com/arcboxlabs/arcbox/commit/7dfb7854c3965190f48b332ddcdfd3b50afc5d66))
* **vsock:** async handshake wait for HV vsock connections ([a7f5fbf](https://github.com/arcboxlabs/arcbox/commit/a7f5fbf94bd5840ce0dc4d1d24785a10c82a80ba))
* **vsock:** propagate guest OP_SHUTDOWN F_SEND as socketpair SHUT_WR ([493ffe9](https://github.com/arcboxlabs/arcbox/commit/493ffe9cda208f1b790efee711708bab89259add))
* **vsock:** remove cross-thread poll_vsock_rx from inject_vsock_connect ([ddbb49a](https://github.com/arcboxlabs/arcbox/commit/ddbb49a3d403d0f2d740dc12cbae8e266d60b131))
* **vsock:** restore direct OP_REQUEST injection with deferred fallback ([fa33c5b](https://github.com/arcboxlabs/arcbox/commit/fa33c5b82cb0085c813915204412b27eb5d496e7))
* **vsock:** swallow EINVAL alongside ENOTCONN on F_SEND shutdown ([c79121a](https://github.com/arcboxlabs/arcbox/commit/c79121a663601139036106bf2a65cd4d86353985))
* **vz:** three real bugs — start() race, panics on framework probes ([11d44a1](https://github.com/arcboxlabs/arcbox/commit/11d44a1d057e7c0b0bb24081e186d33c37585244))


### Performance Improvements

* **fs:** VirtioFS tuning — adaptive negative cache TTL, cache profiles, READDIRPLUS (ABX-289) ([8b28bb2](https://github.com/arcboxlabs/arcbox/commit/8b28bb2d361d25249e29bbaab4f3be5861e4239b))
* **net-inject:** drain each inline conn per pass, cap fairness per conn ([86ca055](https://github.com/arcboxlabs/arcbox/commit/86ca055e6dc1369ab5c3c27cc09063434ac07791))
* **net-inject:** implement VIRTIO_F_EVENT_IDX IRQ suppression ([0b29229](https://github.com/arcboxlabs/arcbox/commit/0b29229159444831d44896f6f91adef59101b269))
* **net-inject:** mergeable RX via readv — 22.7 Gbps Host→VM ([19997e1](https://github.com/arcboxlabs/arcbox/commit/19997e1ec2e4022339469dbb2f9d0654c18cdf40))
* **net:** enable MRG_RXBUF + large frames — 10.4 Gbps receiver ([436b810](https://github.com/arcboxlabs/arcbox/commit/436b810126a95425246df4f09b78da09721804a8))
* **net:** increase VZ network MTU from 1500 to 4000 ([#198](https://github.com/arcboxlabs/arcbox/issues/198)) ([d94359d](https://github.com/arcboxlabs/arcbox/commit/d94359d4ab61e8a770265237fe0a7c3798e9289f))
* **net:** raise rx-inject batch size from 64 to 256 ([834a36e](https://github.com/arcboxlabs/arcbox/commit/834a36e891e7f6c38ad68a171e808113166b9844))
* **net:** raise rx-inject COALESCE_TIMEOUT from 50 µs to 200 µs ([a047150](https://github.com/arcboxlabs/arcbox/commit/a047150ad24aa6cb73290f4a59de7d240851e6e4))
* **net:** TCP fast path — bypass smoltcp for established connections ([#203](https://github.com/arcboxlabs/arcbox/issues/203)) ([bb29e21](https://github.com/arcboxlabs/arcbox/commit/bb29e21e749ce9d3475eb05fa5b4b15f687660a9))
* **net:** tune buffer sizes and poll interval for higher throughput ([#191](https://github.com/arcboxlabs/arcbox/issues/191)) ([0469191](https://github.com/arcboxlabs/arcbox/commit/04691913d910e449ebd47e1249a79d5c96090ca3))
* **net:** tune SO_RCVBUF/SO_SNDBUF to 4 MiB on inbound TCP streams ([c4a80ac](https://github.com/arcboxlabs/arcbox/commit/c4a80ac579afad115053b86e80628f2687bfaaa8))
* **virtio-net:** reuse persistent RX scratch buffer ([950d6bb](https://github.com/arcboxlabs/arcbox/commit/950d6bb68879c5bc7b4057bc9afc651521d9a35c))
* **vmm:** I/O request merging with preadv/pwritev ([c6ccda3](https://github.com/arcboxlabs/arcbox/commit/c6ccda311e666227cc7b3abf31b855d57514202a))
* **vmm:** increase virtio-net RX queue size from 256 to 1024 ([3c64232](https://github.com/arcboxlabs/arcbox/commit/3c64232710e56f46e5aac1af9483fd57adf1e762))
* **vmm:** tune net-io backoff and descriptor exhaustion handling ([874fbeb](https://github.com/arcboxlabs/arcbox/commit/874fbeb27b0677ecc6ff6f6e59c9d6db72a88719))


### Reverts

* disable GSO header fields — guest drops packets ([aba44a4](https://github.com/arcboxlabs/arcbox/commit/aba44a46d562ebd16e8a7f5489a9a8267eefa63e))


### Code Refactoring

* **agent:** sync probe helpers + spawn_blocking for agent readiness ([d698472](https://github.com/arcboxlabs/arcbox/commit/d698472a515049f64c091aeb31650003cfcf137e))
* **dax:** 128MB per-share DAX window, scales with share count ([5ec7993](https://github.com/arcboxlabs/arcbox/commit/5ec799389b098178dc1775d28dd19a63e14af468))
* **net:** delete smoltcp TCP stack from tcp_bridge + datapath ([4237e0a](https://github.com/arcboxlabs/arcbox/commit/4237e0a6552ca51f41464d53fe1c24748b6eea8b))
* **net:** remove smoltcp dependency entirely ([1fd1fe5](https://github.com/arcboxlabs/arcbox/commit/1fd1fe5468bc2dcdcee3d1c0cbdfcb4a37c883c0))
* **net:** rename SmoltcpDevice → FrameClassifier ([663d61a](https://github.com/arcboxlabs/arcbox/commit/663d61ae2433bdd43f5e81d8a254422cfea52be9))
* **net:** route TCP handshake through shim, retire smoltcp paths ([06058a5](https://github.com/arcboxlabs/arcbox/commit/06058a575c0994c76cf6f6c15d43b651ce482143))
* Phase 2 — virtio-bindings, PL011 address fix, vm-superio dep ([715031a](https://github.com/arcboxlabs/arcbox/commit/715031a9ddfbca7d43669da770bb3a8835d5028f))
* **virtio-blk:** split monolithic lib.rs into modules ([ea0630d](https://github.com/arcboxlabs/arcbox/commit/ea0630db0a1f379281cf72114512c15620f057cd))
* **virtio-console:** split monolithic lib.rs into modules ([45be3e5](https://github.com/arcboxlabs/arcbox/commit/45be3e516cd69b41dad5b7498dd6f2b42f67bf09))
* **virtio-fs:** make protocol module private ([a8473d2](https://github.com/arcboxlabs/arcbox/commit/a8473d216ecebad366eb42cc567d926c571aa9ca))
* **virtio-fs:** split monolithic lib.rs into modules ([5b0c7a3](https://github.com/arcboxlabs/arcbox/commit/5b0c7a3c597289cc52256f222cdfa7268d8e8176))
* **virtio-net:** split monolithic lib.rs into modules ([b3f2f3e](https://github.com/arcboxlabs/arcbox/commit/b3f2f3e8fb54f9867b40cfb994b414b922d8d186))
* **virtio-vsock:** split monolithic lib.rs into modules ([217fdbf](https://github.com/arcboxlabs/arcbox/commit/217fdbf3538eba18c9fc98cc61d496bc3c6b9203))
* **virtio:** drop unnecessary pub(crate) on private fields ([27d58fa](https://github.com/arcboxlabs/arcbox/commit/27d58faeb2a1615d67c0afe5491d2a09251cb629))
* **virtio:** extract arcbox-virtio-rng as a per-device crate ([2bce171](https://github.com/arcboxlabs/arcbox/commit/2bce171bc6f8d36f1c70694776e1f8245064d32b))
* **virtio:** extract console + blk crates; move queue to core ([42d1e05](https://github.com/arcboxlabs/arcbox/commit/42d1e05f299916b0128fb055d319ddabe3f8eb40))
* **virtio:** extract foundational types into arcbox-virtio-core ([85e14e8](https://github.com/arcboxlabs/arcbox/commit/85e14e863b79fce8bf8e0e284add720e7e46bbf2))
* **virtio:** extract net + fs + vsock crates — pattern-1 split done ([63f1b42](https://github.com/arcboxlabs/arcbox/commit/63f1b42a6e1d6a52c383a81ab8351864981070a0))
* **virtio:** promote GuestMemWriter to arcbox-virtio + add DeviceCtx ([5d31a95](https://github.com/arcboxlabs/arcbox/commit/5d31a952df4ba218ac302689a70b19d2110b211f))
* **virtio:** replace hand-written VirtIO constants with virtio-bindings ([270c0f7](https://github.com/arcboxlabs/arcbox/commit/270c0f71a4268ec83374a1a1e2f31be4ac28bb21))
* **vmm:** extract bridge NIC handlers into device/bridge_nic submodule ([83d8ea4](https://github.com/arcboxlabs/arcbox/commit/83d8ea450682c6c0c23a6bae643e955b8cee429b))
* **vmm:** extract HVC block I/O into darwin_hv/hvc_blk submodule ([faca9b9](https://github.com/arcboxlabs/arcbox/commit/faca9b9d0f7d9d00d118b6af47b1b078759737ce))
* **vmm:** extract InlineConnSinkAdapter into its own submodule ([7f27873](https://github.com/arcboxlabs/arcbox/commit/7f278739759f8ab47200c98a97a41564eb3536ca))
* **vmm:** extract net worker lifecycle and blk dispatch from DeviceManager ([7bccbdd](https://github.com/arcboxlabs/arcbox/commit/7bccbdd0ab460808758ab55eb4eb0f670edf7e38))
* **vmm:** extract PSCI handler into darwin_hv/psci submodule ([e8118b1](https://github.com/arcboxlabs/arcbox/commit/e8118b158bfd88ade0b0dc5adc9aa2a8b3c4e23f))
* **vmm:** extract vCPU run loop into darwin_hv/vcpu_loop submodule ([98a0c3f](https://github.com/arcboxlabs/arcbox/commit/98a0c3f2f6797e98a5c85115a11106b301d7b3fa))
* **vmm:** extract VirtIO MMIO state into device/mmio_state submodule ([bcdb8cd](https://github.com/arcboxlabs/arcbox/commit/bcdb8cd008462a350f26067dba1844a5b1438729))
* **vmm:** finish vsock — move vsock_manager + port poll_rx_injection ([837fa55](https://github.com/arcboxlabs/arcbox/commit/837fa552931de635b06ef077d50cf6a1f9abba8d))
* **vmm:** migrate bridge NIC (TX+RX) onto VirtioNet ([1daf66e](https://github.com/arcboxlabs/arcbox/commit/1daf66e766209ff02b147ca2f5b67879606dceb1))
* **vmm:** migrate primary NIC TX onto VirtioNet, drop dead methods ([72210cf](https://github.com/arcboxlabs/arcbox/commit/72210cfc709a7010ab69578d9cfe71e6223a45ad))
* **vmm:** split darwin_hv — extract Pl011, GuestRam, network, VcpuContext ([bc87f45](https://github.com/arcboxlabs/arcbox/commit/bc87f45c4d8fc3785036a280714f672961ae2c73))
* **vmm:** split device.rs — extract checksum finalizer submodule ([bd0e4c4](https://github.com/arcboxlabs/arcbox/commit/bd0e4c4be904e69ca170c67e8aa10292ded6af65))
* **vmm:** vsock device owns its connections — drop QueueConfig wart ([32835fb](https://github.com/arcboxlabs/arcbox/commit/32835fb87e2c5d0097ee26a401715c70a70e167c))
* **vsock:** simplify connect path — pure deferred injection ([15b82b4](https://github.com/arcboxlabs/arcbox/commit/15b82b4b3f02aa7728d65164a9bfaa562ff5e478))
* **vz:** remove unused FFI constants, struct, and inherent methods ([223725c](https://github.com/arcboxlabs/arcbox/commit/223725c6f0cfc9c4d3f859e1606aad5a3d98cbd9))


### Tests

* **core:** add hv_e2e example with ping + pause/resume round-trip (ABX-361) ([4e16315](https://github.com/arcboxlabs/arcbox/commit/4e16315e6f528916fc2ae74e898ddc9afa97795e))
* **core:** hv_e2e DAX mount wiring + TempDir fixture hygiene ([a2dfc8b](https://github.com/arcboxlabs/arcbox/commit/a2dfc8b43593ccff7537ab6b11167045126d5b8d))
* **core:** wire hv_e2e against real data_dir so guest boots (ABX-361/362) ([d98af5c](https://github.com/arcboxlabs/arcbox/commit/d98af5c39cbc12f4abd26a472929fffdc054a1a3))
* **net:** adapt to NetworkDatapath/SmoltcpDevice mtu parameter ([acbc728](https://github.com/arcboxlabs/arcbox/commit/acbc728e825b59dcb139b63195232d6f9b7d94a8))
* **net:** add DHCP full-cycle and frame classification datapath tests ([462a2ea](https://github.com/arcboxlabs/arcbox/commit/462a2ead31a459c550b4344972798724aace81df))
* **net:** add mock guest NIC and frame builder test helpers ([d6d68e4](https://github.com/arcboxlabs/arcbox/commit/d6d68e4749a28fc8c854d8a6ce2cdd206baf8492))
* **net:** assert ARP reply content in frame classification test ([0827060](https://github.com/arcboxlabs/arcbox/commit/0827060928aad0f59a7a71614adcf362513defa5))
* **net:** drain poll_fast_path with deadline to deprsk CI flake ([990b8db](https://github.com/arcboxlabs/arcbox/commit/990b8db35749ddfd3a640ae7f79c4d3e93286a4a))


### Documentation

* add HV backend architecture plan with rust-vmm ecosystem evaluation ([5936246](https://github.com/arcboxlabs/arcbox/commit/59362461bba245e31cee0376f47970d36edbb243))
* **agent:** drop stale cache=always reference from DAX mount comment ([0481b36](https://github.com/arcboxlabs/arcbox/commit/0481b36462c72adb7a67bb440cbd502f8ab1a02b))
* **net:** diagnostic results rule out multi-queue as the fix ([26db0dd](https://github.com/arcboxlabs/arcbox/commit/26db0dd698ad829b0ef0a36b4660e624441cb826))
* **net:** host-side profile pinpoints IRQ delivery, not ACK intercept ([b961d64](https://github.com/arcboxlabs/arcbox/commit/b961d64fa9642664d55ff940137d7407c015370b))
* **net:** record measured perf and multi-flow collapse limit ([71f7774](https://github.com/arcboxlabs/arcbox/commit/71f77741626e95ed7d2ec0ab20409c71d31a4556))
* **virtio:** align ASCII diagram boxes in umbrella crate doc ([fa108f1](https://github.com/arcboxlabs/arcbox/commit/fa108f1ffc06bd8db0dfa1642b47a968de5d7e55))
* **virtio:** fix rustdoc intra-doc link warnings in per-device crates ([b82206a](https://github.com/arcboxlabs/arcbox/commit/b82206ab062e05e2cdeb93cdef743a14892f930a))
* **virtio:** mark Phase 2.1 CREDIT_REQUEST as landed ([1e16503](https://github.com/arcboxlabs/arcbox/commit/1e16503abfb924ead0aea9a2b9c2032d5e8f88d3))
* **virtio:** mark Phase 2.2 half-close as landed; note deferred richer state enum ([76b48a7](https://github.com/arcboxlabs/arcbox/commit/76b48a78a6dabe91d7f82bbd3abd5033d1093451))
* **virtio:** mark Phase 3 complete; scope 3.3 to scratch-reuse fix ([ea180f9](https://github.com/arcboxlabs/arcbox/commit/ea180f96ea42f92617530d12d1472729194a69c5))
* **virtio:** mark Phase 3.1 + 3.2 as landed; lock Phase 3.3 design ([31d3da7](https://github.com/arcboxlabs/arcbox/commit/31d3da73284c0ac8aded5b8049aeb5c40a9de235))
* **virtio:** rewrite improvements plan around reasoning, not references ([94b95e3](https://github.com/arcboxlabs/arcbox/commit/94b95e36d85b9630f84ff8538ab299792625617b))
* **vmm:** add SAFETY comments to unsafe blocks in HV backend ([bd38511](https://github.com/arcboxlabs/arcbox/commit/bd38511a682252f576146eb8a9ca944225171329))
* **vmm:** tighten DeviceManager module doc + SAFETY block ([79a8c3e](https://github.com/arcboxlabs/arcbox/commit/79a8c3e169920af2f84c52cd232d9da2d0351e8f))


### Miscellaneous Chores

* **core:** force HV backend until rosetta default is resolved ([c658501](https://github.com/arcboxlabs/arcbox/commit/c658501642fc7c2cfc80a09636df5a8996b140b2))
* fix clippy 1.95 lints workspace-wide ([fb7f1ca](https://github.com/arcboxlabs/arcbox/commit/fb7f1ca8658513b1933bbd2d6d603919874b3f23))
* **net-inject:** align Cargo.toml with workspace inheritance ([cd9fc68](https://github.com/arcboxlabs/arcbox/commit/cd9fc6869ca36bee0722150b488d8ebb1042601e))
* pin boot assets to v0.5.3 (kernel v0.0.12 with HVC driver) ([b496d96](https://github.com/arcboxlabs/arcbox/commit/b496d96b107713f0d608a41964719c7009a24869))
* pin boot assets to v0.5.4 (kernel v0.0.13 with FUSE DAX config) ([9cf67b8](https://github.com/arcboxlabs/arcbox/commit/9cf67b8d5441639476a300a28498bd2b2186f362))
* **virtio-net:** delete dead SocketBackend; refresh plan status ([90b05da](https://github.com/arcboxlabs/arcbox/commit/90b05dac4363e2625fb603b3ad124c842925a160))
* **vmm:** clean up debug diagnostics, dead code, and stale docs ([4d85766](https://github.com/arcboxlabs/arcbox/commit/4d85766d7178357e874c1b310edffd14b4c7dff7))
* **vmm:** move legacy code to #[cfg(test)], remove all dead_code suppressions ([8f774ae](https://github.com/arcboxlabs/arcbox/commit/8f774aeeae2f97410de7076b966ded3cc0725812))
* **vmm:** relax drained atomic ordering, reword drain_all comment ([2a32154](https://github.com/arcboxlabs/arcbox/commit/2a32154c2b8958fac0ac8e0d8a9b11d1308d9d1b))
* **vmm:** retire dead vsock inject path, harden DAX/transport lifecycle ([eb18284](https://github.com/arcboxlabs/arcbox/commit/eb1828437aa8db4d81fdb9b418c88a63b74870eb))

## [0.3.21](https://github.com/arcboxlabs/arcbox/compare/v0.3.20...v0.3.21) (2026-04-06)


### Features

* bump Docker toolchain to 29.3.1 and add VirtioFS cache=always ([#164](https://github.com/arcboxlabs/arcbox/issues/164)) ([f53dc24](https://github.com/arcboxlabs/arcbox/commit/f53dc24b2c0b8103c03fd976c4a2b87aad46f724))
* **cli:** link Docker tools in abctl setup install ([2b552cd](https://github.com/arcboxlabs/arcbox/commit/2b552cd9bacb1ef5caa95ca541dff61c38c9e016))
* **docker:** add explicit /build, /build/prune, and /session routes ([#163](https://github.com/arcboxlabs/arcbox/issues/163)) ([b0039a3](https://github.com/arcboxlabs/arcbox/commit/b0039a33755d98238b3fd377854efe6ee17ade39))
* **guest:** enable multi-platform builds and persistent build cache ([#162](https://github.com/arcboxlabs/arcbox/issues/162)) ([f748d7d](https://github.com/arcboxlabs/arcbox/commit/f748d7d724656ea3cf9c607563b980e3261034ab))
* **virt:** integrate Rosetta x86_64 translation for Apple Silicon VMs ([#160](https://github.com/arcboxlabs/arcbox/issues/160)) ([63d6e78](https://github.com/arcboxlabs/arcbox/commit/63d6e784016e40dc344c91a6035a65591f684d6e))


### Bug Fixes

* **cli:** link and unlink docker CLI tools in brew hooks ([#148](https://github.com/arcboxlabs/arcbox/issues/148)) ([c6c0266](https://github.com/arcboxlabs/arcbox/commit/c6c0266b94af0fdd549b03b04d9c2dc9addf9ffa))
* **cli:** link Docker tools in brew hooks + shared symlink module ([c6c0266](https://github.com/arcboxlabs/arcbox/commit/c6c0266b94af0fdd549b03b04d9c2dc9addf9ffa))

## [0.3.20](https://github.com/arcboxlabs/arcbox/compare/v0.3.19...v0.3.20) (2026-04-05)


### Bug Fixes

* find_bundle_contents walks up to main app Contents ([c9ec890](https://github.com/arcboxlabs/arcbox/commit/c9ec890e66c111271d7c9f3923801652b5011208))
* **net:** spin-retry pool free to prevent silent buffer leak ([fe57f0a](https://github.com/arcboxlabs/arcbox/commit/fe57f0aca510e8897b806bd6dba878e33d9ee27b))

## [0.3.19](https://github.com/arcboxlabs/arcbox/compare/v0.3.18...v0.3.19) (2026-04-01)


### Features

* **dns:** hierarchical compose DNS names matching OrbStack scheme ([#156](https://github.com/arcboxlabs/arcbox/issues/156)) ([6c54184](https://github.com/arcboxlabs/arcbox/commit/6c541840da4c7e4be468f911a80af04222508299))
* **net:** support host.docker.internal DNS and gateway-to-localhost translation ([#157](https://github.com/arcboxlabs/arcbox/issues/157)) ([925897d](https://github.com/arcboxlabs/arcbox/commit/925897d563716745acc24d98870345b0162888a3))


### Bug Fixes

* **net:** replace aliasing UB in PacketPool::alloc with owned PacketRef wrapper ([#147](https://github.com/arcboxlabs/arcbox/issues/147)) ([43a2947](https://github.com/arcboxlabs/arcbox/commit/43a2947c7ebcd3faf3dc7bfd99be9b43b915c88f))

## [0.3.18](https://github.com/arcboxlabs/arcbox/compare/v0.3.17...v0.3.18) (2026-03-31)


### Features

* **route:** replace /sbin/route with PF_ROUTE routing socket ([#145](https://github.com/arcboxlabs/arcbox/issues/145)) ([b4cd605](https://github.com/arcboxlabs/arcbox/commit/b4cd6057579d5dc8ebe81d7ffb9617b163503d44))


### Bug Fixes

* **net:** enable sandbox TCP by seeding smoltcp neighbor cache (ABX-278) ([#144](https://github.com/arcboxlabs/arcbox/issues/144)) ([a7c570f](https://github.com/arcboxlabs/arcbox/commit/a7c570f7cf2e2c1bac8df991dd363c5113767b78))

## [0.3.17](https://github.com/arcboxlabs/arcbox/compare/v0.3.16...v0.3.17) (2026-03-30)


### Features

* **cli:** add _internal subcommand for Homebrew Cask hooks ([#143](https://github.com/arcboxlabs/arcbox/issues/143)) ([f903352](https://github.com/arcboxlabs/arcbox/commit/f90335280a22fafb688265b447b2a1504f09dd82))
* replace dead ACPI/GPIO shutdown with vsock RPC ([#133](https://github.com/arcboxlabs/arcbox/issues/133)) ([6de29c3](https://github.com/arcboxlabs/arcbox/commit/6de29c3ccf567480f90085323ac13fd8286d34e7))


### Bug Fixes

* **sandbox:** enable DNS resolution inside sandboxes ([#135](https://github.com/arcboxlabs/arcbox/issues/135)) ([e7565df](https://github.com/arcboxlabs/arcbox/commit/e7565dfa42101edf343d00b7690794016daef094))

## [0.3.16](https://github.com/arcboxlabs/arcbox/compare/v0.3.15...v0.3.16) (2026-03-30)


### Bug Fixes

* **core:** persistence reliability — atomic writes, error visibility, recovery ([#140](https://github.com/arcboxlabs/arcbox/issues/140)) ([9eef749](https://github.com/arcboxlabs/arcbox/commit/9eef749836e05344f108d1d6c4fac6aa34464974))


### Code Refactoring

* **core,agent:** split vm_lifecycle and agent into module directories (T3) ([#138](https://github.com/arcboxlabs/arcbox/issues/138)) ([30593b2](https://github.com/arcboxlabs/arcbox/commit/30593b2b9b744ac525ed19fdae276acc74b23de2))
* **core:** lifecycle state dedup and event semantics (T2) ([#137](https://github.com/arcboxlabs/arcbox/issues/137)) ([c7e2ec7](https://github.com/arcboxlabs/arcbox/commit/c7e2ec76184b93a020256b49706d3d74fb170e80))
* **core:** T7 phase 1 — typed error variants for VMM, snapshot, persistence, lock poisoned ([#141](https://github.com/arcboxlabs/arcbox/issues/141)) ([cdedea7](https://github.com/arcboxlabs/arcbox/commit/cdedea7bec5181a73050c287a85e8ffb31e44c26))
* **daemon:** typed startup phases and HostLayout dedup (T1, T4) ([#136](https://github.com/arcboxlabs/arcbox/issues/136)) ([335602b](https://github.com/arcboxlabs/arcbox/commit/335602b55fa7446c9e986c16bb6f40f67ee8fd28))
* **virt:** T5 — VM convergence: freeze arcbox-vm, typed platform fields ([#139](https://github.com/arcboxlabs/arcbox/issues/139)) ([e35bfe7](https://github.com/arcboxlabs/arcbox/commit/e35bfe70631040077bc1c6647c5aad783a95a019))

## [0.3.15](https://github.com/arcboxlabs/arcbox/compare/v0.3.14...v0.3.15) (2026-03-26)


### Features

* add native k3s support to ArcBox ([#44](https://github.com/arcboxlabs/arcbox/issues/44)) ([f268d88](https://github.com/arcboxlabs/arcbox/commit/f268d8839b28ea9e72e51953d3c798668c1c0e4f))

## [0.3.14](https://github.com/arcboxlabs/arcbox/compare/v0.3.13...v0.3.14) (2026-03-26)


### Features

* **migration:** add local runtime migration flow and fix Docker image load proxying ([#55](https://github.com/arcboxlabs/arcbox/issues/55)) ([03ecf14](https://github.com/arcboxlabs/arcbox/commit/03ecf1493be953d61d2526708fa91b6f3c325fee))


### Bug Fixes

* **daemon:** add visible ^C feedback and double-^C force quit ([#127](https://github.com/arcboxlabs/arcbox/issues/127)) ([bd8e7f0](https://github.com/arcboxlabs/arcbox/commit/bd8e7f0b1e7efd7748d45097501eb2dbacfe26b1))

## [0.3.13](https://github.com/arcboxlabs/arcbox/compare/v0.3.12...v0.3.13) (2026-03-26)


### Features

* **net:** point-to-point TAP networking with ioctl for sandbox isolation ([a78edcf](https://github.com/arcboxlabs/arcbox/commit/a78edcf9a477deb1b3f12ef572af8667aa048783))


### Bug Fixes

* **net:** add serde default for prefix_len backwards compatibility ([bc24efc](https://github.com/arcboxlabs/arcbox/commit/bc24efc8c04d9e7d7aadf8a0e47dfc0ce9cdb557))
* **net:** address review feedback on sandbox networking PR ([9fa5fc7](https://github.com/arcboxlabs/arcbox/commit/9fa5fc76c02a3940b3c6ec4db3c7770a3ee0f500))
* **net:** restore ICMP identifier and filter Echo Reply in proxy ([14928e8](https://github.com/arcboxlabs/arcbox/commit/14928e8dd4a0959046e4e40b0bad41445787349e))
* **test:** use absolute /usr/sbin/ip path in integration tests ([cebed05](https://github.com/arcboxlabs/arcbox/commit/cebed05163871652d427f181c7b367dada6b4fa0))


### Tests

* **net:** add integration tests for point-to-point TAP networking ([357973e](https://github.com/arcboxlabs/arcbox/commit/357973ed693d7a9dbf0ebd05183d71cd33cd870e))


### Documentation

* **contributing:** fix consistency issues and align with Makefile ([#126](https://github.com/arcboxlabs/arcbox/issues/126)) ([2d77d91](https://github.com/arcboxlabs/arcbox/commit/2d77d911cb544591aa537af19c35acd510edb291))


### Miscellaneous Chores

* gitignore profraw/profdata and remove scratch notes ([694d681](https://github.com/arcboxlabs/arcbox/commit/694d6812d91c4d807f930e0164de2db8cfaa71ea))
* **net:** remove dead bridge field and fix per-packet log levels ([03b30ef](https://github.com/arcboxlabs/arcbox/commit/03b30ef26d8b53daed84c1e8fdd57f9807949ddc))

## [0.3.12](https://github.com/arcboxlabs/arcbox/compare/v0.3.11...v0.3.12) (2026-03-26)


### Bug Fixes

* address PR review comments ([866a0cc](https://github.com/arcboxlabs/arcbox/commit/866a0cc9828f26a9a0f0861cd582af6a8cf85c08))
* address second round of review comments ([0b1b5b2](https://github.com/arcboxlabs/arcbox/commit/0b1b5b2c31d7c19bed154415be2a4d1cbd884200))
* **core:** close serial FDs on VM stop instead of leaking via mem::forget ([33f3d5f](https://github.com/arcboxlabs/arcbox/commit/33f3d5f9765a677bc183d25564f9ff2ec324e25e))
* **core:** propagate skip_stop_on_drop to DarwinVm and preserve network cleanup ([f1e84f0](https://github.com/arcboxlabs/arcbox/commit/f1e84f0202e5b93bb7bb24d8505a122d1d35eb36))
* **docker:** forward all non-hop-by-hop headers to guest dockerd ([8b65f2d](https://github.com/arcboxlabs/arcbox/commit/8b65f2de2407872e73836ade0b78ab1325e92155))
* **fs:** replace unaligned pointer casts with read_unaligned in FUSE dispatcher ([8cd1e45](https://github.com/arcboxlabs/arcbox/commit/8cd1e454067b24ef224976cf0355a9d01bfd0837))
* **hypervisor:** use read_unaligned for KVM IO data access ([d20c484](https://github.com/arcboxlabs/arcbox/commit/d20c4840d598a20ea15e4df572499c2efaeb4b48))
* **net:** correct ConnTrack expiry timer using process-wide epoch ([3c9edcb](https://github.com/arcboxlabs/arcbox/commit/3c9edcbcfa0564253ce9f073d7b20574fa3c1978))
* **net:** correct MPMC ring CAS ordering to prevent data race ([8efd12f](https://github.com/arcboxlabs/arcbox/commit/8efd12f4df350e49d53f8b31912f849891d926ea))
* **net:** replace ConnTrack fast cache raw pointers with Arc ([d5d52d6](https://github.com/arcboxlabs/arcbox/commit/d5d52d6313d344bbcf7236f1e00d1dcf37d6c4dc))
* **net:** rewrite MPMC ring as Vyukov bounded queue with per-slot sequences ([2a65966](https://github.com/arcboxlabs/arcbox/commit/2a659661478750ae112376356f7fd02ad48222c6))
* **vm-agent:** close master_fd on fork failure to prevent leak ([9f63bef](https://github.com/arcboxlabs/arcbox/commit/9f63befa7e832739c42bab5cb3eef915529c9ca9))
* **vm-agent:** fix PTY master_fd double-close via ownership transfer ([f7a79b0](https://github.com/arcboxlabs/arcbox/commit/f7a79b055e991d8d5df7a6152b81d5511b2de76e))
* **vm-agent:** import IntoRawFd trait for into_raw_fd() call ([971fdcb](https://github.com/arcboxlabs/arcbox/commit/971fdcbc3ed57fd44ed87c1ed20161e69098943a))
* **vmm:** drop trigger_callback lock before invoking IRQ callback ([b35b14d](https://github.com/arcboxlabs/arcbox/commit/b35b14d4faac78797ae678a1b5701fc457d084e3))

## [0.3.11](https://github.com/arcboxlabs/arcbox/compare/v0.3.10...v0.3.11) (2026-03-26)


### Bug Fixes

* **cli:** remove sfltool resetbtm, fix plist leak, rename app to ArcBox ([#123](https://github.com/arcboxlabs/arcbox/issues/123)) ([e22d3f8](https://github.com/arcboxlabs/arcbox/commit/e22d3f81c1a3eb03f78d00d4d8be427562d0a282))
* **net:** add Copy bound to MpmcRing to prevent soundness hole ([#124](https://github.com/arcboxlabs/arcbox/issues/124)) ([4e18408](https://github.com/arcboxlabs/arcbox/commit/4e18408f0bf922c7166967a1126f274e8a1bd566))


### Code Refactoring

* replace test section dividers with mod blocks ([#121](https://github.com/arcboxlabs/arcbox/issues/121)) ([bfb7a5b](https://github.com/arcboxlabs/arcbox/commit/bfb7a5b38e33021f9e89942d22734d287b391406))

## [0.3.10](https://github.com/arcboxlabs/arcbox/compare/v0.3.9...v0.3.10) (2026-03-26)


### Features

* **helper:** default to persistent mode, add --idle-exit flag ([#117](https://github.com/arcboxlabs/arcbox/issues/117)) ([5ec0b33](https://github.com/arcboxlabs/arcbox/commit/5ec0b333faf3d1ecbb892e8777dc79fd1e6851a2))


### Bug Fixes

* **guest-agent:** raise inherited nofile limits ([#120](https://github.com/arcboxlabs/arcbox/issues/120)) ([d836dbe](https://github.com/arcboxlabs/arcbox/commit/d836dbe83a4da02495d06a9484762b1ed6b2e3b8))
* vmnet relay thread leak, MAC mismatch, and idle backoff ([#115](https://github.com/arcboxlabs/arcbox/issues/115)) ([c91d7fa](https://github.com/arcboxlabs/arcbox/commit/c91d7fabd456ff6cfa2d5254c825eb5b2faffdc8))


### Miscellaneous Chores

* remove visual section dividers from test/small files ([#118](https://github.com/arcboxlabs/arcbox/issues/118)) ([b01b547](https://github.com/arcboxlabs/arcbox/commit/b01b54713299cd0c72f50c3ca2f97b473173ab48))

## [0.3.9](https://github.com/arcboxlabs/arcbox/compare/v0.3.8...v0.3.9) (2026-03-25)


### Features

* **hypervisor:** derive default VM memory from host physical RAM ([af2ae7f](https://github.com/arcboxlabs/arcbox/commit/af2ae7fa08a044f4883f04dee25ccb6a9f922a23))


### Bug Fixes

* address PR review comments (8 items) ([8ab1786](https://github.com/arcboxlabs/arcbox/commit/8ab178658d27341738568d1dc330c30fe652bfe1))
* **fs:** wire negative_cache_ttl from FsConfig through to PassthroughFs ([c11042e](https://github.com/arcboxlabs/arcbox/commit/c11042e505127b8d74c74be0d0c5e1a628beacfd))
* **hypervisor:** address review comments on memory defaults ([930a0bb](https://github.com/arcboxlabs/arcbox/commit/930a0bb2d297750b74bb00f1793848c178f2b166))
* **hypervisor:** resolve cgroup path and align memory to 1 MiB ([68cea43](https://github.com/arcboxlabs/arcbox/commit/68cea436dc7f2b6da3e1b35a5473b52ac88a40c8))
* **net:** integrate timer wheel into datapath loop select! ([b0fa321](https://github.com/arcboxlabs/arcbox/commit/b0fa3210617667c9c543b93290af53b6641808fd))
* resolve all clippy warnings, enforce -D warnings ([#111](https://github.com/arcboxlabs/arcbox/issues/111)) ([da27253](https://github.com/arcboxlabs/arcbox/commit/da272533ae14234bbaaec143cad462b0f977a418))
* update stale test assertion, comments, and config example ([e640cf0](https://github.com/arcboxlabs/arcbox/commit/e640cf04fa30b0baff8aa289172c81184053c26b))
* **virtio:** include virtio-net header in inject_rx_batch, fix warning ([053dd25](https://github.com/arcboxlabs/arcbox/commit/053dd25d16ba36fa8b04ef195eae434fe6d7073a))
* **virtio:** integrate EVENT_IDX into device feature negotiation ([281881d](https://github.com/arcboxlabs/arcbox/commit/281881d9fccd44ea45180bbad8b03f7d965e0e45))
* **virtio:** partition INIT/DESTROY from parallel FUSE dispatch ([48308dd](https://github.com/arcboxlabs/arcbox/commit/48308ddb6eab86b3de43c06b6af6fc951df415bd))
* **virtio:** preserve avail ring order in parallel FUSE dispatch ([6e57fb2](https://github.com/arcboxlabs/arcbox/commit/6e57fb2ec208d7d77eb860d75961cd41622702d6))
* **vmm:** fix coalescing/bitmap ordering, add end-to-end tests ([5dffa3e](https://github.com/arcboxlabs/arcbox/commit/5dffa3ea8e5006ae8d76bc09348735c967b58fd6))
* **vmm:** unify remaining hardcoded memory defaults ([7d9cb27](https://github.com/arcboxlabs/arcbox/commit/7d9cb2703dc0062a80989cc58b28c1a7644d99bf))
* **vmm:** wire CoalescingState into IrqChip.trigger_irq() ([ac569f2](https://github.com/arcboxlabs/arcbox/commit/ac569f2fe3d735c73597717246512f1751febc53))


### Performance Improvements

* **core:** replace serial port 200ms polling with adaptive backoff ([a77ebb9](https://github.com/arcboxlabs/arcbox/commit/a77ebb93dde984a128471fcc79b70fdd8da45bf0))
* **fs:** increase FUSE cache TTL from 1s to 10s ([a81316c](https://github.com/arcboxlabs/arcbox/commit/a81316c80d1315101431d1728aef7f6f08ffe152))
* **net:** add unified timer wheel for flow timeout management ([02c82cd](https://github.com/arcboxlabs/arcbox/commit/02c82cd603ef653cadf67ef8c3b0e824f6a0ecc9))
* **net:** increase smoltcp poll interval from 100ms to 250ms ([acda2f4](https://github.com/arcboxlabs/arcbox/commit/acda2f4b9ce35aa77818dbd22c54b6d9ce241e18))
* **virtio:** enable concurrent FUSE request processing with rayon ([fcd6c3c](https://github.com/arcboxlabs/arcbox/commit/fcd6c3cae40e4decb091570ab99b908470b08eed))
* **virtio:** implement EVENT_IDX and interrupt suppression in VirtQueue ([feb7d51](https://github.com/arcboxlabs/arcbox/commit/feb7d51cb4abc984e9e94ae4a1b9bf2e15d5895b))
* **virtio:** implement TX/RX batch coalescing in virtio-net ([a5f3aa7](https://github.com/arcboxlabs/arcbox/commit/a5f3aa7a6cae260ddc523fdc0c1a5a618e881d4c))
* **vmm:** add timer-based interrupt coalescing to IRQ manager ([a21201d](https://github.com/arcboxlabs/arcbox/commit/a21201dedc93b8f2312440f4ec05bdcdafb5d45c))

## [0.3.8](https://github.com/arcboxlabs/arcbox/compare/v0.3.7...v0.3.8) (2026-03-25)


### Features

* **docker:** GuestConnector trait + proxy integration tests ([#109](https://github.com/arcboxlabs/arcbox/issues/109)) ([1e2730a](https://github.com/arcboxlabs/arcbox/commit/1e2730a7327e03920ec55282d12f52e426399cf0))
* overhaul logging system with unified paths, rotation, and structured output ([cef06d0](https://github.com/arcboxlabs/arcbox/commit/cef06d0dd5af5992a638cdc9f4a1a82ba79cb383))


### Bug Fixes

* **agent:** handle log directory creation failure gracefully ([e86166d](https://github.com/arcboxlabs/arcbox/commit/e86166d96c38cd5b6da4380ab58e4866b42db6c8))
* **cli:** correct tail_lines offset calculation and update docs ([ad00ae9](https://github.com/arcboxlabs/arcbox/commit/ad00ae96c761d300630a928823438d0f576fb4bf))
* **cli:** improve logs command reliability ([9eea7c1](https://github.com/arcboxlabs/arcbox/commit/9eea7c107c74e214e1f051ee25c2319261e670a1))
* **daemon:** start gRPC before stale-state cleanup to prevent desktop timeout ([#107](https://github.com/arcboxlabs/arcbox/issues/107)) ([06edbc0](https://github.com/arcboxlabs/arcbox/commit/06edbc011e7cf22de69474a9308b1e455358279e))
* **helper:** graceful shutdown on idle timeout for log flush ([9ab07ae](https://github.com/arcboxlabs/arcbox/commit/9ab07ae58ffedd08b249c135ee0b77e62d16d09d))
* **logging:** validate config, improve rotation error handling ([388f519](https://github.com/arcboxlabs/arcbox/commit/388f5190cee791ed356b6decd43150db3e1aac08))
* quote YAML description values in skill frontmatters ([7dab741](https://github.com/arcboxlabs/arcbox/commit/7dab741c5882372bfb6dbdbe95684a934d638b54))


### Code Refactoring

* **docker:** split proxy.rs into module directory ([#106](https://github.com/arcboxlabs/arcbox/issues/106)) ([ad4010a](https://github.com/arcboxlabs/arcbox/commit/ad4010a4df3597eda29c832e6f7a007f30c4e2ba))


### Documentation

* add Claude Code skills setup to CONTRIBUTING.md ([d638464](https://github.com/arcboxlabs/arcbox/commit/d638464ac04dc2ef8b1facd8c56978b91706725b))
* add code signing guide to CONTRIBUTING.md ([e04dd8b](https://github.com/arcboxlabs/arcbox/commit/e04dd8be45e71f487cecdc505a1d33312173212a))
* **CLAUDE.md:** update signing instructions and add architecture principles ([931db50](https://github.com/arcboxlabs/arcbox/commit/931db5051f44502831bf7e729298f34e63da7a3f))
* fix log rotation claims and legacy path descriptions ([a6a6919](https://github.com/arcboxlabs/arcbox/commit/a6a69196d9771d148d63fe881b3e3dcb8bf36cc0))
* **helper:** add local development guide and Makefile shortcuts ([848391a](https://github.com/arcboxlabs/arcbox/commit/848391ad0bcb752133479da354423e377ed84a06))


### Miscellaneous Chores

* add pre-commit config, fix clippy warnings in arcbox-logging ([a05bf8b](https://github.com/arcboxlabs/arcbox/commit/a05bf8b8f066cf2e6651adc7177c5a9964ad0e63))
* move agent skills to .agents/skills/ for git sharing ([e39f612](https://github.com/arcboxlabs/arcbox/commit/e39f61290760549b6ce4cc67f1fdb639e629e5df))

## [0.3.7](https://github.com/arcboxlabs/arcbox/compare/v0.3.6...v0.3.7) (2026-03-25)


### Features

* implement sandbox exec with bidirectional streaming ([#80](https://github.com/arcboxlabs/arcbox/issues/80)) ([ad1f616](https://github.com/arcboxlabs/arcbox/commit/ad1f616d67354fc7af054e7942f0df4fdc62ebcc))


### Bug Fixes

* **docker:** repair HTTP upgrade proxy for BuildKit and attach ([#105](https://github.com/arcboxlabs/arcbox/issues/105)) ([bf3768d](https://github.com/arcboxlabs/arcbox/commit/bf3768d317e6471b81364f7855db93ebd607ee4a))

## [0.3.6](https://github.com/arcboxlabs/arcbox/compare/v0.3.5...v0.3.6) (2026-03-24)


### Features

* **api:** enable `devicon` for `IconService` ([#102](https://github.com/arcboxlabs/arcbox/issues/102)) ([315df2a](https://github.com/arcboxlabs/arcbox/commit/315df2aea5fdfbc1ba5d7085ef05a9872fb69ece))


### Bug Fixes

* **daemon:** address review feedback on stale cleanup ([4e9f48c](https://github.com/arcboxlabs/arcbox/commit/4e9f48c8ce660ca739bf9bcf359dfffb23dbf807))
* **daemon:** clean up stale state before startup ([#73](https://github.com/arcboxlabs/arcbox/issues/73)) ([4e9f48c](https://github.com/arcboxlabs/arcbox/commit/4e9f48c8ce660ca739bf9bcf359dfffb23dbf807))
* **log:** clean up guest console log formatting ([#67](https://github.com/arcboxlabs/arcbox/issues/67)) ([6f79688](https://github.com/arcboxlabs/arcbox/commit/6f79688b8a02fe22f20161d480e061b04adb726e))

## [0.3.5](https://github.com/arcboxlabs/arcbox/compare/v0.3.4...v0.3.5) (2026-03-23)


### Bug Fixes

* **agent:** remove blocking ntpd sync from runtime prerequisites ([#95](https://github.com/arcboxlabs/arcbox/issues/95)) ([c5969ff](https://github.com/arcboxlabs/arcbox/commit/c5969fff4c8b37b45ca56cb808edccb0150f048e))

## [0.3.4](https://github.com/arcboxlabs/arcbox/compare/v0.3.3...v0.3.4) (2026-03-23)


### Bug Fixes

* **agent:** disable jailer and update sandbox paths for virtiofs mount ([c4a8355](https://github.com/arcboxlabs/arcbox/commit/c4a8355b1f471997cd6d868fb605a8ee5e712e69))
* **net:** create per-SYN listen sockets for concurrent connections ([#97](https://github.com/arcboxlabs/arcbox/issues/97)) ([65d6a53](https://github.com/arcboxlabs/arcbox/commit/65d6a536adb567339004e22505ceed11482c9bfc))
* **net:** harden outbound network stack (P0 + P1) ([#98](https://github.com/arcboxlabs/arcbox/issues/98)) ([aa0f8dc](https://github.com/arcboxlabs/arcbox/commit/aa0f8dc7c586bd424636d05832d0062370be7bcf))


### Code Refactoring

* **api:** split grpc.rs into per-service modules ([#93](https://github.com/arcboxlabs/arcbox/issues/93)) ([fa597ba](https://github.com/arcboxlabs/arcbox/commit/fa597bacf7269da4f237babe9edda315553976af))

## [0.3.3](https://github.com/arcboxlabs/arcbox/compare/v0.3.2...v0.3.3) (2026-03-22)


### Features

* **api:** add IconService gRPC for container image icon lookups ([6f7abf5](https://github.com/arcboxlabs/arcbox/commit/6f7abf53c6fd2a75f3d92f35aacc86233a865814))


### Bug Fixes

* **api:** bump dimicon to 0.1.0 for stable API ([19aa521](https://github.com/arcboxlabs/arcbox/commit/19aa52152e16c107cbd62bb5b319c9b875bb2723))
* **helper:** add missing cli_link/cli_unlink stubs, rename misleading test ([01c65e4](https://github.com/arcboxlabs/arcbox/commit/01c65e4326cb4e10d617634c4ae8ce23c1313e6b))
* **helper:** harden input validation in validate.rs ([ff57feb](https://github.com/arcboxlabs/arcbox/commit/ff57feb6e5141a525af6a1ad4119e32036d4034f))


### Code Refactoring

* **api:** extract icon-to-response conversion via From&lt;ResolvedIcon&gt; ([4def9a4](https://github.com/arcboxlabs/arcbox/commit/4def9a471d30f5ba4139bb1d338b5effd40c4ea7))
* **api:** rename IconService field `reference` to `fqin` ([34188ad](https://github.com/arcboxlabs/arcbox/commit/34188ad468bc54999df7cbd13e237dc4dafe5529))
* **helper:** apply newtype pattern to validation types ([de9261e](https://github.com/arcboxlabs/arcbox/commit/de9261e03cefcc718243f42a9470268f6e7cf8cb))
* **helper:** push validation to RPC boundary, mutations accept strong types ([1015bc1](https://github.com/arcboxlabs/arcbox/commit/1015bc11f71d38038d2c58ed60ce9d28e35be7dd))
* **helper:** remove separator comments, split rpc_test.rs ([9268410](https://github.com/arcboxlabs/arcbox/commit/92684109022956be62395a1e02569a457e735389))
* **helper:** split validate.rs into per-type modules ([6dc9c29](https://github.com/arcboxlabs/arcbox/commit/6dc9c29b49914d38ac46a8f224493994f32e6a6d))


### Tests

* **helper:** align mock servers with newtype parse pattern ([a856b52](https://github.com/arcboxlabs/arcbox/commit/a856b52f6dca6cb1c18be2d4c12cd6a30942dd25))


### Styles

* cargo fmt arcbox-helper ([340553f](https://github.com/arcboxlabs/arcbox/commit/340553f5d9623cd47b50ea14defddd161f3048de))
* cargo fmt validate/mod.rs ([6ca69db](https://github.com/arcboxlabs/arcbox/commit/6ca69db21c49b987d1c7250471b1d26f2167316e))
* fix import ordering in icon_test ([ce20b5c](https://github.com/arcboxlabs/arcbox/commit/ce20b5c0361f99ede05c6f114aa69497f312bc37))

## [0.3.2](https://github.com/arcboxlabs/arcbox/compare/v0.3.1...v0.3.2) (2026-03-21)


### Features

* daemon self-provisioning — desktop becomes pure display layer ([#89](https://github.com/arcboxlabs/arcbox/issues/89)) ([eedcdeb](https://github.com/arcboxlabs/arcbox/commit/eedcdebe4376fe9030d51479c6ac2c7407f9b19d))

## [0.3.1](https://github.com/arcboxlabs/arcbox/compare/v0.3.0...v0.3.1) (2026-03-20)


### Bug Fixes

* **helper:** move clippy allow to function level for CI compatibility ([e4fca5d](https://github.com/arcboxlabs/arcbox/commit/e4fca5df96c7e9eabb54d9580de5f86a1c35c0dd))
* **helper:** use isize::try_from instead of function-level allow for cast ([945b2bb](https://github.com/arcboxlabs/arcbox/commit/945b2bb83f8b70ab63d276f37ce2025962d68cc7))


### Styles

* cargo fmt peer_auth.rs ([bd6c8ab](https://github.com/arcboxlabs/arcbox/commit/bd6c8abbf4a1619718f7cb94a30f3012c772458b))

## [0.3.0](https://github.com/arcboxlabs/arcbox/compare/v0.2.7...v0.3.0) (2026-03-20)


### Bug Fixes

* **ci:** ad-hoc sign arcbox-helper before smoke test ([#84](https://github.com/arcboxlabs/arcbox/issues/84)) ([ba6759a](https://github.com/arcboxlabs/arcbox/commit/ba6759a01c7b95138bd7492144d28fbbae0ebf61))


### Code Refactoring

* **daemon:** decouple arcbox-desktop from arcbox-daemon ([#81](https://github.com/arcboxlabs/arcbox/issues/81)) ([afe6593](https://github.com/arcboxlabs/arcbox/commit/afe6593cf7cc826a5640cf719001414300bb6a9f))

## [0.2.7](https://github.com/arcboxlabs/arcbox/compare/v0.2.6...v0.2.7) (2026-03-18)


### Bug Fixes

* **net:** add retry logic to route reconciler ([a23bee1](https://github.com/arcboxlabs/arcbox/commit/a23bee1fd7586efa8a69349688b10b5b145b3e44))
* **net:** add retry logic to route reconciler ([#77](https://github.com/arcboxlabs/arcbox/issues/77)) ([0f8d304](https://github.com/arcboxlabs/arcbox/commit/0f8d304b8791ecd3d48ae8910fd4138bc5ba6da9))


### Styles

* **net:** fix formatting in route reconciler and daemon ([f2d3a9d](https://github.com/arcboxlabs/arcbox/commit/f2d3a9ddf37643329e1919e6eac7edf1536fb44e))

## [0.2.6](https://github.com/arcboxlabs/arcbox/compare/v0.2.5...v0.2.6) (2026-03-17)


### Code Refactoring

* **net:** replace text parsing with system APIs for route management ([#76](https://github.com/arcboxlabs/arcbox/issues/76)) ([5b226fa](https://github.com/arcboxlabs/arcbox/commit/5b226fa95fa83abc523009e7f5ce41954b03f204))

## [0.2.5](https://github.com/arcboxlabs/arcbox/compare/v0.2.4...v0.2.5) (2026-03-17)


### Features

* **cli:** add `abctl doctor` diagnostic command ([078f62f](https://github.com/arcboxlabs/arcbox/commit/078f62f4b725856e58f539ea8259ff1b2872ae82))
* **cli:** add `abctl uninstall` command ([16c19f5](https://github.com/arcboxlabs/arcbox/commit/16c19f5c78dda3af9d45a0af1ab9c283f53a5460))


### Bug Fixes

* **cli:** add login item approval reset as explicit uninstall step ([7a87010](https://github.com/arcboxlabs/arcbox/commit/7a87010d47523d48ac1627ec04f14b6a3d2cd3e5))
* **daemon:** address review findings for stale state cleanup ([66f0afc](https://github.com/arcboxlabs/arcbox/commit/66f0afc4b2478232dd01e366b7904f5e9ac25f32))


### Documentation

* **readme:** add desktop, discord, telegram, and docs badges ([21a49c3](https://github.com/arcboxlabs/arcbox/commit/21a49c3ae6828e7ec21f6e5c738aa9efdf853796))


### Styles

* cargo fmt ([4ae09c7](https://github.com/arcboxlabs/arcbox/commit/4ae09c756d7c3d0ca2d38c01870f6c7a1d1cd453))

## [0.2.4](https://github.com/arcboxlabs/arcbox/compare/v0.2.3...v0.2.4) (2026-03-17)


### Bug Fixes

* **daemon:** clean up stale state before startup ([3e48003](https://github.com/arcboxlabs/arcbox/commit/3e48003baaca58b37224958e31a7086a3ba258ee))
* **net:** change custom network stack subnet from 192.168.64.0/24 to 10.0.2.0/24 ([c1dd477](https://github.com/arcboxlabs/arcbox/commit/c1dd477c2fe5c356bbe6ecaaa0339edb7d5bdbf1))


### Miscellaneous Chores

* **release:** include all conventional commit types in changelog ([aa81671](https://github.com/arcboxlabs/arcbox/commit/aa8167194ac45011ea70f4cde1273f4c21a9ed7e))

## [0.2.3](https://github.com/arcboxlabs/arcbox/compare/v0.2.2...v0.2.3) (2026-03-16)


### Bug Fixes

* **build:** remove restricted com.apple.vm.networking entitlement ([63f96d2](https://github.com/arcboxlabs/arcbox/commit/63f96d2d03e8af620363b28d5094098c3f191e48))

## [0.2.2](https://github.com/arcboxlabs/arcbox/compare/v0.2.1...v0.2.2) (2026-03-16)


### Features

* **net:** daemon owns route lifecycle via arcbox-helperctl ([7979aac](https://github.com/arcboxlabs/arcbox/commit/7979aac6b720a9ca6022397ac6aae1c551d4f3bf))


### Bug Fixes

* **net:** robust bridge NIC detection, skip primary interface by name ([0f03c22](https://github.com/arcboxlabs/arcbox/commit/0f03c221fd421f0d6b83e277ceff707c94187603))
* **net:** update route_reconciler to call ArcBoxHelper (single binary) ([985e1cd](https://github.com/arcboxlabs/arcbox/commit/985e1cdfdef41340d4da05ca67f0905ac640c792))

## [0.2.1](https://github.com/arcboxlabs/arcbox/compare/v0.2.0...v0.2.1) (2026-03-16)


### Bug Fixes

* **net:** add com.apple.vm.networking entitlement for vmnet bridge ([d46802c](https://github.com/arcboxlabs/arcbox/commit/d46802ce8599541ef3793dfaead21adc8ec7522a))

## [0.2.0](https://github.com/arcboxlabs/arcbox/compare/v0.1.12...v0.2.0) (2026-03-15)


### Features

* **agent:** add guest DNS server and Docker event listener (Phase 1) ([ef9da60](https://github.com/arcboxlabs/arcbox/commit/ef9da603dfa2023c1b514e72309259debd9d0dc1))
* **dns:** add arcbox-dns crate for shared DNS packet parsing ([b55ed1f](https://github.com/arcboxlabs/arcbox/commit/b55ed1f6eaebf44ff519b2caa8d5813fe596b72b))
* **dns:** share DNS hosts table between host DnsService and VMM datapath (Phase 2) ([fa4440e](https://github.com/arcboxlabs/arcbox/commit/fa4440e6f9b9622e4105d299b75180caf2d79844))
* **helper:** add privileged helper for utun/route operations ([32d2c23](https://github.com/arcboxlabs/arcbox/commit/32d2c23c68c77018337fa0a67695d7956ec1ce3c))
* **helper:** privileged network helper with fd passing and hello handshake ([746aaea](https://github.com/arcboxlabs/arcbox/commit/746aaea2eff8974ac685339c89248fa22fd24f3e))
* **net:** add L3 tunnel service with bidirectional utun routing (Phase 3) ([13499c6](https://github.com/arcboxlabs/arcbox/commit/13499c664a65e9c274678463de7f6fca390e74a8))
* **net:** daemon uses helper for utun creation via fd passing (Step 2) ([2264fcb](https://github.com/arcboxlabs/arcbox/commit/2264fcbca9240a1bd230a5b034ab7a1166a715d7))
* **net:** L3 direct routing via vmnet bridge (replaces utun approach) ([1b05e30](https://github.com/arcboxlabs/arcbox/commit/1b05e304b77cefa337cbd8b0f8d9c35accccaee8))
* **net:** proxy ARP on bridge NIC, eliminates gateway IP discovery ([a03d5c8](https://github.com/arcboxlabs/arcbox/commit/a03d5c8653201d0a8db1b36ceac80d3aa991c6a8))
* **net:** sandbox DNS, broader subnet routing, dead code cleanup (Phase 4-6) ([96b7b73](https://github.com/arcboxlabs/arcbox/commit/96b7b7357af0d8cc4db5637c813930bc507b73aa))
* **vmm:** integrate L3 tunnel into VMM and runtime (Phase 3) ([1edb1fc](https://github.com/arcboxlabs/arcbox/commit/1edb1fc6a06738439c7313a90996966eea7581ad))


### Bug Fixes

* address new review comments ([3ed2c3b](https://github.com/arcboxlabs/arcbox/commit/3ed2c3b15d0d92394fad84a84dcaae6e9c78368f))
* address PR review comments ([11116d0](https://github.com/arcboxlabs/arcbox/commit/11116d0b4d38d2c5afa913215a70b734345ee8d0))
* **net:** avoid 198.18.0.0 IP conflict, fix cross-compile and async issues ([84db1df](https://github.com/arcboxlabs/arcbox/commit/84db1dfc9c7c162dd2cb07643aeb725f330c1c9b))
* **net:** confirmed macOS utun write() does not deliver to local IP stack ([2d49809](https://github.com/arcboxlabs/arcbox/commit/2d49809bddb8bd4e3aac8a149e4c96cc77757a4c))
* **net:** switch utun read loop to blocking poll+read (AsyncFd unreliable on PF_SYSTEM) ([3c69fa9](https://github.com/arcboxlabs/arcbox/commit/3c69fa94bf4e50bf9bd72941073b69f7360c1681))
* **net:** use 240.0.0.1 (Class E reserved) for utun address, macOS requires IPv4 for -interface routes ([4164592](https://github.com/arcboxlabs/arcbox/commit/4164592a25d46165c71960dcbe517459b9d64e1e))
* resolve remaining PR review comments ([2f4adc4](https://github.com/arcboxlabs/arcbox/commit/2f4adc41e4747663caf7f2f66ff878843b83b88a))


### Miscellaneous Chores

* bump version to 0.2.0 ([d365921](https://github.com/arcboxlabs/arcbox/commit/d3659210a97e91969b93e2c820d6a1bf230eba34))

## [0.1.12](https://github.com/arcboxlabs/arcbox/compare/v0.1.11...v0.1.12) (2026-03-14)


### Features

* **agent:** add blanket iptables FORWARD rules for sandbox subnet ([599e596](https://github.com/arcboxlabs/arcbox/commit/599e5969ea5256538a7c9e3689421172166cf9a0))
* **agent:** add PortForwardManager for iptables DNAT sandbox port forwarding ([98d58df](https://github.com/arcboxlabs/arcbox/commit/98d58df71d6a8b52e233692cc46e7898a6d30f2d))
* **agent:** integrate PortForwardManager into sandbox dispatch and cleanup ([be9d3e6](https://github.com/arcboxlabs/arcbox/commit/be9d3e63a7c40108c63b73c99777c71c6a539b50))
* **agent:** register sandbox DNS in /etc/hosts on create/restore ([27fc18d](https://github.com/arcboxlabs/arcbox/commit/27fc18d03e7d82960a1d5b11157d5bae94645436))
* **core:** add sandbox_port_forward/remove to AgentClient ([b44a64a](https://github.com/arcboxlabs/arcbox/commit/b44a64a34988f2b233051ad08be4b35fc48388d1))
* **proto:** add SandboxPortForward request/response messages ([7a6643f](https://github.com/arcboxlabs/arcbox/commit/7a6643fb0d7576ecaeecc7561fdcbf29121da8e4))
* **wire:** add SandboxPortForward request/response message types ([35e4517](https://github.com/arcboxlabs/arcbox/commit/35e4517fbed5025cd955117da523b9d63d9942fa))


### Bug Fixes

* **agent:** decode stop/remove request once, return 400 on failure ([d118d76](https://github.com/arcboxlabs/arcbox/commit/d118d76021f4f9c8f92b93fdac1cc36bcabaf963))
* **agent:** delete iptables rules before removing allocation entry ([b9446d3](https://github.com/arcboxlabs/arcbox/commit/b9446d3eefa3071befd03f5a571cc61cda588f0e))
* **agent:** export dns module from lib.rs for sandbox.rs access ([9bbb4b0](https://github.com/arcboxlabs/arcbox/commit/9bbb4b010f0f887f13b8848122d00b39ef50aed6))
* **agent:** fix borrow conflict and SandboxId type mismatch in port forward ([b7f5031](https://github.com/arcboxlabs/arcbox/commit/b7f5031acb11245cda6e4583e3f42667bb45b64a))
* **agent:** fix dns marker matching and support IP upsert ([2e45aae](https://github.com/arcboxlabs/arcbox/commit/2e45aaefb6bd904c4bd47e891fa5fbd501fbb0d9))
* **docker:** always update context on enable to fix stale socket path ([8a0c45e](https://github.com/arcboxlabs/arcbox/commit/8a0c45e8d98df79f18f9f89969395955bf70620d))
* scope app token to arcbox-desktop repo for cross-repo push ([d2dc78a](https://github.com/arcboxlabs/arcbox/commit/d2dc78ae2668e2d753a89311ac3799f55cb7912a))

## [0.1.11](https://github.com/arcboxlabs/arcbox/compare/v0.1.10...v0.1.11) (2026-03-13)


### Bug Fixes

* correct musl linker name for aarch64 target ([dde3ad9](https://github.com/arcboxlabs/arcbox/commit/dde3ad95f55939c3d9246d1aadcd498361c351eb))

## [0.1.10](https://github.com/arcboxlabs/arcbox/compare/v0.1.9...v0.1.10) (2026-03-13)


### Bug Fixes

* use token-authenticated git clone for arcbox-desktop push ([fc332f2](https://github.com/arcboxlabs/arcbox/commit/fc332f25857769f2efbeb69977a8c80ea76a6610))

## [0.1.9](https://github.com/arcboxlabs/arcbox/compare/v0.1.8...v0.1.9) (2026-03-13)


### Bug Fixes

* install protobuf in build-agent job ([8c904ea](https://github.com/arcboxlabs/arcbox/commit/8c904ea833ce2bd4b6fcf3b82b85f852e52bf20e))
* set git identity for update-desktop job ([295b896](https://github.com/arcboxlabs/arcbox/commit/295b896a6a832069638ee9a08ee623624d996049))

## [0.1.8](https://github.com/arcboxlabs/arcbox/compare/v0.1.7...v0.1.8) (2026-03-13)


### Bug Fixes

* remove --locked from release builds ([ded024e](https://github.com/arcboxlabs/arcbox/commit/ded024e7f339b0b514850ab732831f9b8b5ecb01))
* update Cargo.lock in release-please PR and restore --locked builds ([3b84b26](https://github.com/arcboxlabs/arcbox/commit/3b84b26233b1e5bd069521750920aa553393375a))
* use arcbox-labs bot for Cargo.lock commits ([657f684](https://github.com/arcboxlabs/arcbox/commit/657f6843dc32ca2a62fba614b8351f9b4fe55e1f))

## [0.1.7](https://github.com/arcboxlabs/arcbox/compare/v0.1.6...v0.1.7) (2026-03-13)


### Features

* migrate from release-plz to release-please ([51472a2](https://github.com/arcboxlabs/arcbox/commit/51472a2158b6998c674adff6ddb782efd63ced7f))
* **release:** auto-update arcbox-desktop version on release ([500aee5](https://github.com/arcboxlabs/arcbox/commit/500aee506413466e74784f066209e7352263a3fb))


### Bug Fixes

* align workspace dependency versions and add release-please markers ([71f11af](https://github.com/arcboxlabs/arcbox/commit/71f11af918f91d125464e83c472521f5d0ba79d5))
* **core:** show full path in missing binary error messages ([0f598ea](https://github.com/arcboxlabs/arcbox/commit/0f598ea91b71040e8c48fd7455895e5550483a8e))
* **release:** decouple tag/release creation from release-plz ([5cf5b5c](https://github.com/arcboxlabs/arcbox/commit/5cf5b5c7ccb00a8845168356e124e04e94ee7dd9))
* use patch bump for pre-1.0 releases ([7d54bd1](https://github.com/arcboxlabs/arcbox/commit/7d54bd1924cfd1f3f6792e460422257bb1b444e7))

## [Unreleased]

## [0.1.5] - 2026-03-09

### Features
- Auto-install CLI tools from app bundle on Desktop launch ([#34](https://github.com/arcboxlabs/arcbox/pull/34))
- Replace vsock busy-polling with AsyncFd, add full-duplex split API ([#45](https://github.com/arcboxlabs/arcbox/pull/45))

### Bug Fixes
- Graceful shutdown with CancellationToken ([#39](https://github.com/arcboxlabs/arcbox/pull/39))
- Remove tracked-but-ignored boot assets from git index

### Refactor
- Extract DHCP server into standalone arcbox-dhcp crate ([#43](https://github.com/arcboxlabs/arcbox/pull/43))
- Remove unnecessary unsafe from NAT translate functions ([#29](https://github.com/arcboxlabs/arcbox/pull/29))
- Reorganize ~/.arcbox/ directory layout ([#48](https://github.com/arcboxlabs/arcbox/pull/48))

### Miscellaneous
- Add SAFETY comments to all unsafe blocks in arcbox-vz ([#26](https://github.com/arcboxlabs/arcbox/pull/26))
- Add release-plz for automated releases ([#40](https://github.com/arcboxlabs/arcbox/pull/40))
- Disable crates.io publish for now
- Clean up Cargo.toml dependency declarations
