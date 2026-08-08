# Changelog

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
