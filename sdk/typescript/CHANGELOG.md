# Changelog

## [0.1.3](https://github.com/arcboxlabs/arcbox/compare/sdk-typescript-v0.1.2...sdk-typescript-v0.1.3) (2026-08-14)


### Documentation

* **rpc:** the template catalog is served, not contract-only ([#617](https://github.com/arcboxlabs/arcbox/issues/617)) ([e4c55e1](https://github.com/arcboxlabs/arcbox/commit/e4c55e1418ff806d623bbbe036a37a077187d81d))

## [0.1.2](https://github.com/arcboxlabs/arcbox/compare/sdk-typescript-v0.1.1...sdk-typescript-v0.1.2) (2026-08-11)


### Features

* **api:** list sandbox exposed ports (CORE-102) ([#585](https://github.com/arcboxlabs/arcbox/issues/585)) ([e40e57a](https://github.com/arcboxlabs/arcbox/commit/e40e57af1005bdfe5f339abd22c511ad24f3bf81))
* **sdk-ts:** Template catalog client (CORE-107) ([#604](https://github.com/arcboxlabs/arcbox/issues/604)) ([817ab96](https://github.com/arcboxlabs/arcbox/commit/817ab96771829da668aef7f6df0d3a9024a8a243))
* **sdk:** commands.list and ports.waitForPort for TypeScript ([ebb06aa](https://github.com/arcboxlabs/arcbox/commit/ebb06aaf9912714c3e15ae7307bc08e3db9f4243))
* **sdk:** directory watch stream for TypeScript ([17818b2](https://github.com/arcboxlabs/arcbox/commit/17818b26241906871a644361e03dd0fdd8215aad))
* **sdk:** E2B-compatible surface as @arcbox/sandbox/e2b and arcbox.e2b ([#589](https://github.com/arcboxlabs/arcbox/issues/589)) ([fc55512](https://github.com/arcboxlabs/arcbox/commit/fc55512444bc5eaa042db86e6237d40cbd8d0f46))
* **sdk:** events, setLifecycle, and capabilities for TypeScript ([729e815](https://github.com/arcboxlabs/arcbox/commit/729e8158656008abb7348d701fd78efc45074e2a))
* **sdk:** filesystem path verbs for TypeScript ([c44edd5](https://github.com/arcboxlabs/arcbox/commit/c44edd551494a7f25b4cd0d2da27e1367c5d55d5))
* **sdk:** offset-resume across stream death for TypeScript output ([743c373](https://github.com/arcboxlabs/arcbox/commit/743c373319e4ef3f76d3bad2623b8d2283c3029a))
* **sdk:** PTY, stdin, and command re-attach for TypeScript ([5a301e0](https://github.com/arcboxlabs/arcbox/commit/5a301e0587bbea5ba36f883b2325b7d29375f473))
* **sdk:** snapshot and exposed-port clients in both SDKs ([#588](https://github.com/arcboxlabs/arcbox/issues/588)) ([ed932f9](https://github.com/arcboxlabs/arcbox/commit/ed932f989db83d4f08ddd49dbe4b37a2df26761f))
* **sdk:** waitForLog on the command handle for TypeScript ([c57b56c](https://github.com/arcboxlabs/arcbox/commit/c57b56ccd2fd81e40a10cf910e00bfb24d8d1daf))


### Bug Fixes

* **sdk:** bound connect()'s waits with one overall deadline (TypeScript) ([ec883a7](https://github.com/arcboxlabs/arcbox/commit/ec883a76251c22629eae83a3fa98f6857bdeb9d7))
* **sdk:** review round 1 — timeout validation, deadline ordering, retention docs ([bdc158e](https://github.com/arcboxlabs/arcbox/commit/bdc158e38fdd49d0d78be2645eed23f800ecc621))
* **sdk:** satisfy the strict lint set in the TS e2e watch loop ([9b55655](https://github.com/arcboxlabs/arcbox/commit/9b556551c360d85273bd2e221beb6b8a93007027))
* **sdk:** treat server-signaled unavailable as stream death; kill leaked stdin feeds ([73bced0](https://github.com/arcboxlabs/arcbox/commit/73bced0312660dab6ff9cbd769049a0ca45ea9d0))
* **sdk:** validate the connect timeout knob at the boundary ([7883a84](https://github.com/arcboxlabs/arcbox/commit/7883a8431d43ad6869727865eae4337e144b1259))


### Tests

* **sdk:** extend the gated e2e suites with the phase 2a surface ([3a656ff](https://github.com/arcboxlabs/arcbox/commit/3a656fff43528924c044749c0b5d601bcafe6280))
* **sdk:** extend the gated e2e suites with the phase 2b surface ([3329a21](https://github.com/arcboxlabs/arcbox/commit/3329a219cf0a02f9297a0e27d29dd2b6aa101916))
* **sdk:** template catalog e2e phase in both SDK suites (CORE-107) ([#609](https://github.com/arcboxlabs/arcbox/issues/609)) ([e59fc0e](https://github.com/arcboxlabs/arcbox/commit/e59fc0e3bd90c2804114f4161e27d80600ac000b))


### Documentation

* **sdk:** state the whole-second wire granularity on the waitForPort knob ([a54746e](https://github.com/arcboxlabs/arcbox/commit/a54746e10b9c44b9ac1a6cd442eddee092b82fc8))


### Continuous Integration

* **sdk:** gate the TypeScript and Python SDKs on every PR ([f1cda25](https://github.com/arcboxlabs/arcbox/commit/f1cda25ff028a6a9cdb8ac898d58455faf1a6776))

## [0.1.1](https://github.com/arcboxlabs/arcbox/compare/sdk-typescript-v0.1.0...sdk-typescript-v0.1.1) (2026-08-08)


### Features

* **sdk:** ArcBox entry point and Sandbox handle ([fbf6ce4](https://github.com/arcboxlabs/arcbox/commit/fbf6ce4ecd99b5bd7082c0317e5526a8f98a6410))
* **sdk:** commands and files data-plane namespaces ([038b674](https://github.com/arcboxlabs/arcbox/commit/038b6741e501940435a69210fc33cb91f09e9c74))
* **sdk:** generate sandbox_v1 wire types via buf + protoc-gen-es ([2ec52ee](https://github.com/arcboxlabs/arcbox/commit/2ec52eed2fb47c6d1ba5507f6a34a0e512d0c149))
* **sdk:** hello-world e2e gate and README ([e85bf73](https://github.com/arcboxlabs/arcbox/commit/e85bf73023830c18da9b0d7a78eb23c9d94c72e2))
* **sdk:** scaffold @arcbox/sandbox package tooling ([5aa3134](https://github.com/arcboxlabs/arcbox/commit/5aa3134bd21d2e447e5ff1478f6c956e33bcf1b1))
* **sdk:** UDS Connect transport and typed error mapping ([9241860](https://github.com/arcboxlabs/arcbox/commit/9241860d1e8f2cfeb5fc02f25d6d5e3f852e2e30))


### Bug Fixes

* **ci:** pin the publish jobs' actions and drop their cache/credential surface ([2fb3528](https://github.com/arcboxlabs/arcbox/commit/2fb3528e2b52bc5472eac82151293a13d013ed7a))
* **sdk:** clean up on failed create and widen the dispose not-found gate ([8aae4de](https://github.com/arcboxlabs/arcbox/commit/8aae4ded91afae0536ed96741f1b1931851afe50))
* **sdk:** honor ARCBOX_PROFILE when resolving the default socket ([31cf8e5](https://github.com/arcboxlabs/arcbox/commit/31cf8e5626cdc6cbdc723cf3a02e7de83bf151b0))
* **sdk:** include node types explicitly so the build config compiles ([18798cb](https://github.com/arcboxlabs/arcbox/commit/18798cba124759bc6c6da7423e072a4ba09806be))
* **sdk:** make the PAUSING connect test witness the settle poll ([8f5761d](https://github.com/arcboxlabs/arcbox/commit/8f5761df1edaee66d4e3bcf73b34d7aaf62b1d5f))
* **sdk:** report retained-output truncation and deadline the signal RPC ([b0d05cf](https://github.com/arcboxlabs/arcbox/commit/b0d05cfae622ee22437355ff36df912ad49c4136))
* **sdk:** resolve the writeBytes default mode SDK-side ([2ca4c8c](https://github.com/arcboxlabs/arcbox/commit/2ca4c8c2a4b31fc4e394473e1219aeb8c1f8fa21))
* **sdk:** stop connect() from waiting on READY for a PAUSING sandbox ([b50c39a](https://github.com/arcboxlabs/arcbox/commit/b50c39a592eb6387c6f2c3bfc3a02dc46c3e6821))


### Code Refactoring

* **sdk:** resolve the sukka lint findings in handwritten code ([1611b15](https://github.com/arcboxlabs/arcbox/commit/1611b156622036045a2e97a10bc18712be41273a))


### Documentation

* **sdk:** mark the npm publish workflow pending in the release flow ([bbda08a](https://github.com/arcboxlabs/arcbox/commit/bbda08ad2c260f61893f62cccc49473816d34e23))


### Styles

* **sdk:** apply the biome formatter ([6c2aff2](https://github.com/arcboxlabs/arcbox/commit/6c2aff2dbde4b39ccbe3157c290a5160d4dd84bd))


### Build System

* **sdk:** register @arcbox/sandbox as a release-please component ([d36184a](https://github.com/arcboxlabs/arcbox/commit/d36184a2f35f742b2f0f2a5e6df1143b87ea718e))


### Miscellaneous Chores

* **sdk:** build with bunchee instead of tsc ([4a6fae7](https://github.com/arcboxlabs/arcbox/commit/4a6fae7fb0c64c3b2a46cbe516bce7af3adfb3af))
* **sdk:** drop .js import extensions via bundler-mode resolution ([48924c0](https://github.com/arcboxlabs/arcbox/commit/48924c036ba0906bb14cf71f48b7b3b0864f0712))
* **sdk:** swap prettier and typescript-eslint for biome and sukka ([4aab59f](https://github.com/arcboxlabs/arcbox/commit/4aab59f571c93be2a5c1fc5e477dd7f8de433d42))
