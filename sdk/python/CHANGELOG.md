# Changelog

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
