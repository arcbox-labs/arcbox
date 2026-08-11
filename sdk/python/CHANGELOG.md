# Changelog

## [0.1.2](https://github.com/arcboxlabs/arcbox/compare/sdk-python-v0.1.1...sdk-python-v0.1.2) (2026-08-11)


### Features

* **api:** list sandbox exposed ports (CORE-102) ([#585](https://github.com/arcboxlabs/arcbox/issues/585)) ([e40e57a](https://github.com/arcboxlabs/arcbox/commit/e40e57af1005bdfe5f339abd22c511ad24f3bf81))
* **sdk-py:** Template catalog client (CORE-107) ([#605](https://github.com/arcboxlabs/arcbox/issues/605)) ([a405f39](https://github.com/arcboxlabs/arcbox/commit/a405f39b82c8640b3f76973ea7c13fee5a797b8e))
* **sdk:** commands.list and ports.wait_for_port for Python ([ad13faa](https://github.com/arcboxlabs/arcbox/commit/ad13faac347ce2189cca396998a44b1b02fa3225))
* **sdk:** directory watch stream for Python ([b770d32](https://github.com/arcboxlabs/arcbox/commit/b770d323faa53e3c01f461dafbffb2c17fc4532d))
* **sdk:** E2B-compatible surface as @arcbox/sandbox/e2b and arcbox.e2b ([#589](https://github.com/arcboxlabs/arcbox/issues/589)) ([fc55512](https://github.com/arcboxlabs/arcbox/commit/fc55512444bc5eaa042db86e6237d40cbd8d0f46))
* **sdk:** events, set_lifecycle, and capabilities for Python ([2e1d778](https://github.com/arcboxlabs/arcbox/commit/2e1d77840b3142e6969bcdab404de9fbc6dc4a98))
* **sdk:** filesystem path verbs for Python ([dff8cbd](https://github.com/arcboxlabs/arcbox/commit/dff8cbd603dc520e5a45db5f77949ebfb5397321))
* **sdk:** offset-resume across stream death for Python output ([729d412](https://github.com/arcboxlabs/arcbox/commit/729d41274c0b7348cd0a3ccd23fbd6543b324ac4))
* **sdk:** PTY, stdin, and command re-attach for Python ([5650ac7](https://github.com/arcboxlabs/arcbox/commit/5650ac706a5458107ca119eb3b96366071d4d30e))
* **sdk:** snapshot and exposed-port clients in both SDKs ([#588](https://github.com/arcboxlabs/arcbox/issues/588)) ([ed932f9](https://github.com/arcboxlabs/arcbox/commit/ed932f989db83d4f08ddd49dbe4b37a2df26761f))
* **sdk:** wait_for_log on the command handle for Python ([633d62d](https://github.com/arcboxlabs/arcbox/commit/633d62df4d85055775b6f38b58f76ec5cdc4a3c3))


### Bug Fixes

* **sdk:** bound connect()'s waits with one overall deadline (Python) ([2b6180a](https://github.com/arcboxlabs/arcbox/commit/2b6180aff7b3909a19b56acbbf2c18c450e4c2b9))
* **sdk:** expose __version__ in the Python package ([55cf895](https://github.com/arcboxlabs/arcbox/commit/55cf895e05747d2a1d72a3061791f8d011a6604f))
* **sdk:** keep NaN and infinity out of the wait_for_log transport deadline ([7c7861b](https://github.com/arcboxlabs/arcbox/commit/7c7861baa8f924b6ae790702603776205f3a9543))
* **sdk:** review round 1 — timeout validation, deadline ordering, retention docs ([bdc158e](https://github.com/arcboxlabs/arcbox/commit/bdc158e38fdd49d0d78be2645eed23f800ecc621))
* **sdk:** review round 2 — bound silent streams, first-frame drop classification ([8bbe9b8](https://github.com/arcboxlabs/arcbox/commit/8bbe9b8c53d64d29f44b568a6b0fcff398d58bbe))
* **sdk:** treat server-signaled unavailable as stream death; kill leaked stdin feeds ([73bced0](https://github.com/arcboxlabs/arcbox/commit/73bced0312660dab6ff9cbd769049a0ca45ea9d0))
* **sdk:** validate the connect timeout knob at the boundary ([7883a84](https://github.com/arcboxlabs/arcbox/commit/7883a8431d43ad6869727865eae4337e144b1259))


### Tests

* **sdk:** extend the gated e2e suites with the phase 2a surface ([3a656ff](https://github.com/arcboxlabs/arcbox/commit/3a656fff43528924c044749c0b5d601bcafe6280))
* **sdk:** extend the gated e2e suites with the phase 2b surface ([3329a21](https://github.com/arcboxlabs/arcbox/commit/3329a219cf0a02f9297a0e27d29dd2b6aa101916))
* **sdk:** pin the inf-disables-the-bound branch via the recorded read timeout ([6ad91a8](https://github.com/arcboxlabs/arcbox/commit/6ad91a8d63560e601cf0d0b99343a1fad3d8a075))
* **sdk:** port the TS connect-test corrections to the Python twin ([5e33ab0](https://github.com/arcboxlabs/arcbox/commit/5e33ab01448ab36cb4b90fa37995df1ede2dc8e6))
* **sdk:** template catalog e2e phase in both SDK suites (CORE-107) ([#609](https://github.com/arcboxlabs/arcbox/issues/609)) ([e59fc0e](https://github.com/arcboxlabs/arcbox/commit/e59fc0e3bd90c2804114f4161e27d80600ac000b))


### Documentation

* **sdk:** state the whole-second wire granularity on the waitForPort knob ([a54746e](https://github.com/arcboxlabs/arcbox/commit/a54746e10b9c44b9ac1a6cd442eddee092b82fc8))


### Continuous Integration

* **sdk:** gate the TypeScript and Python SDKs on every PR ([f1cda25](https://github.com/arcboxlabs/arcbox/commit/f1cda25ff028a6a9cdb8ac898d58455faf1a6776))

## [0.1.1](https://github.com/arcboxlabs/arcbox/compare/sdk-python-v0.1.0...sdk-python-v0.1.1) (2026-08-08)


### Features

* **sdk:** async Sandbox surface — create/connect/list, commands, files ([c049c2f](https://github.com/arcboxlabs/arcbox/commit/c049c2fa1ca7f70ea17b8ef75fe15db358a344e0))
* **sdk:** Connect-over-httpx transport core (async tree) ([21d1e41](https://github.com/arcboxlabs/arcbox/commit/21d1e41aea0ec4dc0ab5def6bd3d19a80b6b708f))
* **sdk:** generate the sandbox wire types into arcbox/_gen ([95e0057](https://github.com/arcboxlabs/arcbox/commit/95e0057e8f31a5e055cf79505ea52cfd794b34f2))
* **sdk:** generated sync tree and the public export surface ([76cd305](https://github.com/arcboxlabs/arcbox/commit/76cd305781d20ae2fb4a902ebd802691a06a8485))
* **sdk:** hand-written public DTOs and their wire mappings ([27bc47c](https://github.com/arcboxlabs/arcbox/commit/27bc47c0926ac650abd545298414568c0f494b47))
* **sdk:** scaffold the Python package with uv, ruff, pyright gates ([c40ceac](https://github.com/arcboxlabs/arcbox/commit/c40ceacdc1ccbfb31ff1698379e3ece46f04f1f9))
* **sdk:** typed errors, connection resolution, Connect framing ([e398113](https://github.com/arcboxlabs/arcbox/commit/e398113a3bf39cbfc6e854b728e3de713a4dfbf3))


### Bug Fixes

* **ci:** pin the publish jobs' actions and drop their cache/credential surface ([2fb3528](https://github.com/arcboxlabs/arcbox/commit/2fb3528e2b52bc5472eac82151293a13d013ed7a))
* **sdk:** close SDK-owned HTTP clients deterministically ([db31c22](https://github.com/arcboxlabs/arcbox/commit/db31c22352ae17eee7595cc77be4856301bac19b))
* **sdk:** honor sub-second wait_for_exit deadlines ([5a1c9f2](https://github.com/arcboxlabs/arcbox/commit/5a1c9f2479bc4e3228ef723e9f31a6c318f68fd1))
* **sdk:** make early exit from commands.output releasable at the break ([ea39831](https://github.com/arcboxlabs/arcbox/commit/ea398313d8fbda86cfa570f8fada7ea00bc815fc))
* **sdk:** poll before sleeping in the sub-second wait tail ([0d35448](https://github.com/arcboxlabs/arcbox/commit/0d354483ce32bcbb64d2ca9586331f0589554cde))
* **sdk:** require the terminal EndStreamResponse in client_stream ([51c5251](https://github.com/arcboxlabs/arcbox/commit/51c52511836d1664c760f7bfdefd6f996b416989))
* **sdk:** route non-Connect JSON error bodies to the HTTP fallback ([0c631f4](https://github.com/arcboxlabs/arcbox/commit/0c631f482d9e2d445e25864d832afb0ee49164fd))
* **sdk:** stop connect() from waiting on READY for a PAUSING sandbox ([1c64253](https://github.com/arcboxlabs/arcbox/commit/1c642536da2e7681a806c3427ebb329ce364d59c))


### Tests

* **sdk:** connection resolution, error boundary, envelope framing ([2325fa7](https://github.com/arcboxlabs/arcbox/commit/2325fa722d28739af33482de771aa960612c2407))
* **sdk:** mock-daemon run/files loops, sync parity, gated e2e ([4892888](https://github.com/arcboxlabs/arcbox/commit/489288879b9c68656725d0b63c560052a25dee15))


### Documentation

* **sdk:** mark the PyPI publish workflow pending and record the bootstrap caveats ([d240b92](https://github.com/arcboxlabs/arcbox/commit/d240b92b1e4277f7c41f1dd30f89a608e5c7eb05))
* **sdk:** Python SDK README and scoped prek hooks ([d57536c](https://github.com/arcboxlabs/arcbox/commit/d57536c1b5fdf640259e4bbb698b02365c36bc53))
* **sdk:** satisfy ruff's markdown code-block formatting in the README ([969d5e9](https://github.com/arcboxlabs/arcbox/commit/969d5e935caca5aef67ff3ba7040ca2281788309))


### Build System

* **sdk:** register arcbox (Python) as a release-please component ([3b44845](https://github.com/arcboxlabs/arcbox/commit/3b44845028754de220e5a94bae54096daf6cddcf))


### Miscellaneous Chores

* **sdk:** reflow gen_proto for the 100-column format config ([31d82e9](https://github.com/arcboxlabs/arcbox/commit/31d82e95adcba17cebf4d7b69580ac758cdbbd22))
