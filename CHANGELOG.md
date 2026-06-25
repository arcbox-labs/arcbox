# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
