# Changelog

## [0.1.2](https://github.com/arcboxlabs/arcbox/compare/fleet-agent-v0.1.1...fleet-agent-v0.1.2) (2026-07-16)


### Bug Fixes

* **fleet:** dedup TLS crypto stack on aws-lc-rs (tonic 0.14, russh aws-lc-rs) ([#395](https://github.com/arcboxlabs/arcbox/issues/395)) ([9542819](https://github.com/arcboxlabs/arcbox/commit/9542819448d02e60d1a5c406d4d272ea35ac684d))

## [0.1.1](https://github.com/arcboxlabs/arcbox/compare/fleet-agent-v0.1.0...fleet-agent-v0.1.1) (2026-07-15)


### Features

* **fleet:** drain and self-update on gateway update pushes ([72f4e5d](https://github.com/arcboxlabs/arcbox/commit/72f4e5d5c22ffd6fa062ded3707052c3db3cac86))
* **fleet:** install-service — user LaunchAgent for start-on-login on macOS ([082a663](https://github.com/arcboxlabs/arcbox/commit/082a663d13a218659057ca4bb885504476c4f79c))
* **fleet:** prepare macos_runner_image through the daemon's ImagePull ([192a230](https://github.com/arcboxlabs/arcbox/commit/192a2300bee770c09b546700ce7263f0e47b7e97))
* **fleet:** quick self-update — CDN-driven manual update ([cab36b7](https://github.com/arcboxlabs/arcbox/commit/cab36b77d04e1df82e53727c83c035724eb640c9))
* **fleet:** redesign gateway handshake around agent_version ([8a4e68e](https://github.com/arcboxlabs/arcbox/commit/8a4e68efa75d622985aa72a9502f6abde03a9423))
* **fleet:** route darwin jobs through the macOS VM backend ([6f416e8](https://github.com/arcboxlabs/arcbox/commit/6f416e8882f8d1f490089fce2c6ba3540e1cb268))
* **fleet:** self-update executor and managed binary layout ([73844b3](https://github.com/arcboxlabs/arcbox/commit/73844b35bef529cca5b954aabe2649667ad2e373))
* **fleet:** sync self-update proto and report host platform ([4836062](https://github.com/arcboxlabs/arcbox/commit/4836062730722c4449de6dffadcfe8c739f32186))
* **fleet:** vm_mode and macos_runner_image settings (RUN-31) ([1200a49](https://github.com/arcboxlabs/arcbox/commit/1200a49c1958cfd5fcf696efe689d2434e6284ba))
* **fleet:** VmRunner — daemon probe, ephemeral macOS guest lifecycle, ssh exec ([2167dd5](https://github.com/arcboxlabs/arcbox/commit/2167dd5cf7ccf73a2f5f0e5a879fd2b087c3e7e7))


### Bug Fixes

* **fleet:** point default gateway at gateway.fleet.arcbox.dev ([d419b46](https://github.com/arcboxlabs/arcbox/commit/d419b467785e25c6134a3064a81eb7d685dbd8af))
* **fleet:** send the first heartbeat before waiting on the Attach response ([b4cd6cf](https://github.com/arcboxlabs/arcbox/commit/b4cd6cffee50ec5d3f3cd74840d52de3bce6a7f2))


### Code Refactoring

* **fleet:** isolate socketless lifecycle commands under quick ([#391](https://github.com/arcboxlabs/arcbox/issues/391)) ([2245979](https://github.com/arcboxlabs/arcbox/commit/22459798a2ed0bd92f633f6bcfe1cc4deba81cee))
* **fleet:** move install-service under quick ([2102d79](https://github.com/arcboxlabs/arcbox/commit/2102d790f02b59e1a970902b9983a21a0fdc36be))


### Tests

* **fleet:** ignored end-to-end VM round-trip against a live daemon ([5092827](https://github.com/arcboxlabs/arcbox/commit/5092827a55402696ea348a98d50123ae9764b370))


### Documentation

* **fleet:** correct self-update trust model and swap semantics ([224eedb](https://github.com/arcboxlabs/arcbox/commit/224eedbd7a11b41d68a1592593bb505123ea0d8b))


### Styles

* **fleet:** rustfmt update.rs ([7d6fb40](https://github.com/arcboxlabs/arcbox/commit/7d6fb40e6c5a322af49f25bf053d568be5dfac12))

## 0.1.0 (2026-07-14)


### Features

* **fleet:** add FleetImageService.Prepare; runner image applies via preparation ([c318676](https://github.com/arcboxlabs/arcbox/commit/c318676eb4075410c1ec86209d26ee3e9d324dcb))
* **fleet:** add FleetStateService to the control-plane contract (RUN-35) ([4249640](https://github.com/arcboxlabs/arcbox/commit/424964095821d5722851cd19eed13fa5df8f0e4e))
* **fleet:** AgentState — push observable agent state to Watch subscribers ([cf4da21](https://github.com/arcboxlabs/arcbox/commit/cf4da215e2102fdf0602e6fc3d2c3fc1bc64843e))
* **fleet:** cross-platform runner agent skeleton ([f7e8113](https://github.com/arcboxlabs/arcbox/commit/f7e8113f45e69d19d42398caf2d7ba3ffba7bb4b))
* **fleet:** Docker-based Linux runner support ([4d66d34](https://github.com/arcboxlabs/arcbox/commit/4d66d34a8eca39deafa7ed5da7232af7574c9368))
* **fleet:** fall back to local Docker on macOS when ArcBox is unresponsive ([7ec107e](https://github.com/arcboxlabs/arcbox/commit/7ec107eea46098c881b6c5a640b82826b1cd474b))
* **fleet:** hold offer verdicts until the gateway settles them ([5b7b71e](https://github.com/arcboxlabs/arcbox/commit/5b7b71e9581411b8c3626dbd4cb50de26684d19e))
* **fleet:** live-settable agent configuration via FleetSettingsService (RUN-35) ([4e2a1d3](https://github.com/arcboxlabs/arcbox/commit/4e2a1d3b8b7f985120c30f71dafcd548eeb5f088))
* **fleet:** local gRPC control-plane API on agent.sock (RUN-35 slice 1) ([1b70b37](https://github.com/arcboxlabs/arcbox/commit/1b70b3717ca4f87e3d6c970d1324faf176859868))
* **fleet:** offer/reject protocol, agent as admission authority ([cb44fae](https://github.com/arcboxlabs/arcbox/commit/cb44faef3661929302bdee2a2725b6272b843e0a))
* **fleet:** park visibly when the gateway rejects the credential ([94a8ea4](https://github.com/arcboxlabs/arcbox/commit/94a8ea425b77e8f9df8f22f7c2f18bd51bdd0dbe))
* **fleet:** participate setting — detach from the fleet without unenrolling ([9133ffa](https://github.com/arcboxlabs/arcbox/commit/9133ffafddec88eed4cffd475e3d3e84d802ce91))
* **fleet:** port process-group cancel, graceful shutdown, token-file to offer/reject agent ([a63efc7](https://github.com/arcboxlabs/arcbox/commit/a63efc77ce2a108ec7802fe955a3292150661d76))
* **fleet:** prepare CLI verb streaming preparation progress ([4ad1987](https://github.com/arcboxlabs/arcbox/commit/4ad1987ecfaf07fd7f14a11a830aaa54e63d42b6))
* **fleet:** read enrollment token from file or stdin, not just argv ([8906c39](https://github.com/arcboxlabs/arcbox/commit/8906c3989d12a1bbe207394e9b5317040333b42f))
* **fleet:** resend offer verdicts until the gateway acks ([2e8d376](https://github.com/arcboxlabs/arcbox/commit/2e8d376ba8d572078357af4fac008ccd13b61944))
* **fleet:** scaffold local control-plane proto crate (RUN-35) ([1561507](https://github.com/arcboxlabs/arcbox/commit/15615071871d286e795f8889047ec00c1eb89af0))
* **fleet:** stop runners cleanly on SIGTERM/SIGINT ([659d7b4](https://github.com/arcboxlabs/arcbox/commit/659d7b40fdb8e7a2b2a1feddaa2ac1f78940d795))
* **fleet:** store the machine credential in the OS keychain on macOS/Windows ([2390f3d](https://github.com/arcboxlabs/arcbox/commit/2390f3d566b212745ddafb5814171c5660aa3342))
* **fleet:** unenroll decommissions the machine at the gateway ([bc6f2af](https://github.com/arcboxlabs/arcbox/commit/bc6f2afa9322bb1ecd63cd1cde7c1eb48bc8ea34))
* **fleet:** verify docker by pulling the runner image at startup ([51557fb](https://github.com/arcboxlabs/arcbox/commit/51557fba291293e4da70cba44ca22b7f611a6902))
* **release:** independent fleet-agent release train ([2e97137](https://github.com/arcboxlabs/arcbox/commit/2e971370c52326da304545cd4c7c8484cb48b45d))


### Bug Fixes

* **fleet:** admit jobs per capacity pool to match gateway reservation ([3605e14](https://github.com/arcboxlabs/arcbox/commit/3605e14c9f512835b06ee390684896c3016c9f41))
* **fleet:** always route linux jobs through Docker for isolation ([2a5e6b5](https://github.com/arcboxlabs/arcbox/commit/2a5e6b5b5d85f72478c05979fa2c83fa8f81e731))
* **fleet:** apply gateway first in UpdateSettings for all-or-nothing writes ([7295ced](https://github.com/arcboxlabs/arcbox/commit/7295cedafccd4332ca8799f1f5ac70ece5055d97))
* **fleet:** close disconnect race and un-abortable reconnect timeout ([bba655d](https://github.com/arcboxlabs/arcbox/commit/bba655d65ae9d39b9f2b9fe0abd39780782b6b7c))
* **fleet:** close gateway-vs-enroll race with a State::Enrolling gate ([8db90d5](https://github.com/arcboxlabs/arcbox/commit/8db90d5357a71eff71fcd483c921f7ec2759c8c2))
* **fleet:** connect to ArcBox socket on macOS, fix comments ([33c953d](https://github.com/arcboxlabs/arcbox/commit/33c953d98c45aa0b4567a62fb25740a813d0e406))
* **fleet:** correct re-entrant attachment lifecycle in the control plane ([f541544](https://github.com/arcboxlabs/arcbox/commit/f541544e4d17d083d56230f0adfb25495697a8f9))
* **fleet:** create credential temp file 0600 from the start ([54a7ef8](https://github.com/arcboxlabs/arcbox/commit/54a7ef8ee01ea27669c1abd9bb84bfadb4c757cf))
* **fleet:** don't probe docker during enrollment ([baff099](https://github.com/arcboxlabs/arcbox/commit/baff099976be02e1dcb23d9819909bb68ac371ba))
* **fleet:** drop Windows support from arcbox-fleet-agent ([6ee8f01](https://github.com/arcboxlabs/arcbox/commit/6ee8f01ed2794afbfeffe81992b018797003d785))
* **fleet:** give the data dir the owner-only barrier on headless writes ([31c26fd](https://github.com/arcboxlabs/arcbox/commit/31c26fdf9d4d611747c06129b6619d4900483130))
* **fleet:** kill the whole runner process group on cancel ([329afd3](https://github.com/arcboxlabs/arcbox/commit/329afd377b57691e9b061cfe848da86ea9274824))
* **fleet:** make CredentialStore::new infallible ([0866ea1](https://github.com/arcboxlabs/arcbox/commit/0866ea1c368d943854d2fc0d31b36922ff91149d))
* **fleet:** make ProvisionRunner handling idempotent on job_id ([3196ab6](https://github.com/arcboxlabs/arcbox/commit/3196ab6f359c3ff14745edca5e6683f72d621369))
* **fleet:** move control-plane serving to a new `serve` subcommand ([67bd668](https://github.com/arcboxlabs/arcbox/commit/67bd6681f4d1b51298bc7c26573533e2cb02c5a8))
* **fleet:** observe cancellation at every stage and await runner teardown ([0f4015a](https://github.com/arcboxlabs/arcbox/commit/0f4015aa5572914f8e41db5372f4bf82bd762f5f))
* **fleet:** persist enroll credential only after winning the control-plane race ([8f0fb75](https://github.com/arcboxlabs/arcbox/commit/8f0fb75a7a8caf1635d0b9ec1c3656cbc5502615))
* **fleet:** persist runner supervisor across attach reconnects ([ef30bee](https://github.com/arcboxlabs/arcbox/commit/ef30beed82480230182922aae58060d08e7c9a35))
* **fleet:** persist settings before credential in Enroll (RUN-35) ([c867b9a](https://github.com/arcboxlabs/arcbox/commit/c867b9a8e6c064a9b2d627c661479db6602dfc1c))
* **fleet:** reconnect backoff reset, reject max_concurrent=0, atomic credential write ([9a7c96b](https://github.com/arcboxlabs/arcbox/commit/9a7c96be1f99afca332b4fc5567114b9b7a8d31e))
* **fleet:** refuse Enroll while a disconnect is tearing down ([7786dc1](https://github.com/arcboxlabs/arcbox/commit/7786dc17e1d67dd667039e0daeb7cdece863a5a3))
* **fleet:** refuse gateway changes while a credential exists ([b3b0719](https://github.com/arcboxlabs/arcbox/commit/b3b0719ad2acacfe14047da2f00491358164742d))
* **fleet:** refuse insecure credential storage on non-Unix ([add1fdf](https://github.com/arcboxlabs/arcbox/commit/add1fdf70513a6765f6a603f217b089ce2e79273))
* **fleet:** reject non-positive load ceiling at config parse ([989df8b](https://github.com/arcboxlabs/arcbox/commit/989df8b84d4b14aaf2f2f38563f77a50c19bcd1c))
* **fleet:** release in-flight job on runner task panic ([22ed07e](https://github.com/arcboxlabs/arcbox/commit/22ed07e51a1f3e4f43e087b46b43320fdd54d64b))
* **fleet:** remove orphaned container before reusing its name ([e34be79](https://github.com/arcboxlabs/arcbox/commit/e34be7984f766fcedfa7bf207be1088605c9703a))
* **fleet:** require finite load ceiling, scope keychain credential by gateway ([f7c58e1](https://github.com/arcboxlabs/arcbox/commit/f7c58e1726180523240f51db33d534caf8dce0da))
* **fleet:** scope disconnect's credential clear to the attachment's gateway ([0323ad7](https://github.com/arcboxlabs/arcbox/commit/0323ad71f1ce4c57bf304db9a2f31f7466769cbd))
* **fleet:** stop docker_mode=auto reading as a perpetual pending change ([a33065d](https://github.com/arcboxlabs/arcbox/commit/a33065d1d270621281184f741ee8ec5a512533c8))
* **fleet:** treat redelivered offers as duplicates until the verdict settles ([3bd37c0](https://github.com/arcboxlabs/arcbox/commit/3bd37c058195270442616c85d970cd37a06b250e))
* **fleet:** use pullable actions-runner image as default ([e5578c4](https://github.com/arcboxlabs/arcbox/commit/e5578c43878a85a4cde08c9b1c921f08c725124b))
* **fleet:** validate runner_image against Docker capabilities on UpdateSettings ([32deedb](https://github.com/arcboxlabs/arcbox/commit/32deedb8f6a21670960820c3c20f2d24b9cb28b0))


### Code Refactoring

* **fleet:** drop max_concurrent from DockerCapabilities ([7d6fa7b](https://github.com/arcboxlabs/arcbox/commit/7d6fa7bd63213b9ba4a4216497df6438f6c91bbb))
* **fleet:** extract spawn_shutdown_signal shared by run and serve ([3a5a322](https://github.com/arcboxlabs/arcbox/commit/3a5a3228470a824d08d2fd599d742e92b5534ac8))
* **fleet:** fold atomic JSON persist into fsutil::write_json_atomic ([203752a](https://github.com/arcboxlabs/arcbox/commit/203752ac52a3071dcb04a4f5fdb5525f59132041))
* **fleet:** fold owner-only write into write_json_atomic ([bcd415b](https://github.com/arcboxlabs/arcbox/commit/bcd415b9ad9e5aa2afb4eaa7baf0c045ed0100e9))
* **fleet:** rename Disconnect to Unenroll ([36f17e2](https://github.com/arcboxlabs/arcbox/commit/36f17e286604ee12c9d8799b70d86a4f5d323522))
* **fleet:** rename host runner_dir_present to runner_script_present ([4de100e](https://github.com/arcboxlabs/arcbox/commit/4de100eadbff9c905cabbe476e01bc047326bda7))
* **fleet:** rename runner_image to linux_runner_image ([00f89db](https://github.com/arcboxlabs/arcbox/commit/00f89db57c120902ed7b2fdd7ae01efafd2e68ef))
* **fleet:** replace DockerCapabilities with plain arch list ([b877391](https://github.com/arcboxlabs/arcbox/commit/b8773912461516011201a92e36b0884202343f00))
* **fleet:** reuse docker_mode_from_wire instead of re-deriving it ([488862b](https://github.com/arcboxlabs/arcbox/commit/488862b48249c7346bf20cd3b4e20a48f17491ed))
* **fleet:** route AgentState settings access through two accessors ([d783130](https://github.com/arcboxlabs/arcbox/commit/d783130eb5f8e0045ffd86045c03932cbd279e9f))


### Tests

* **fleet:** stall enroll round-trip on a real socket to fix flaky gate tests ([d0120e4](https://github.com/arcboxlabs/arcbox/commit/d0120e445bcc8dd502e2efc484753202a84da9c7))


### Documentation

* **fleet:** fix broken endpoint_for doc link to gateway_target ([eb67ffb](https://github.com/arcboxlabs/arcbox/commit/eb67ffb89b7dbf3399d397b72a898fa6b581de14))
* **fleet:** sync vendored proto + correct enroll token help ([4916374](https://github.com/arcboxlabs/arcbox/commit/4916374495e89c6f09ed58c41e2419609287d9b0))


### Continuous Integration

* **fleet:** enforce additive-only control-plane proto with buf breaking ([0637f19](https://github.com/arcboxlabs/arcbox/commit/0637f1923a042ee29f2ed046bec32e74cf1e6d1c))


### Miscellaneous Chores

* **fleet:** lint control.proto with buf ([3e57a44](https://github.com/arcboxlabs/arcbox/commit/3e57a44af36c250d62530972db7cd4bedddf2a11))
* **fleet:** sync vendored gateway proto — Keepalive ack for Cloudflare (PLAT-34) ([9579907](https://github.com/arcboxlabs/arcbox/commit/9579907cd129c28988b10bc5d7e9120a59b5454b))
* **fleet:** sync vendored gateway proto — Unenroll RPC, ack doc wording ([e2b8144](https://github.com/arcboxlabs/arcbox/commit/e2b81440ac839c332ef2cd3c94b20d0dbb8ea299))
* **release:** reset fleet-agent version train to 0.0.0 ([e21516a](https://github.com/arcboxlabs/arcbox/commit/e21516aaf5bcad1e441f46e3203a833dab6c1a8a))
