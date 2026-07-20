# Changelog

## [1.1.0](https://github.com/michaeldmitry/flaplint/compare/v1.0.0...v1.1.0) (2026-07-20)


### Features

* add a pebble plan sink ([0d91a2d](https://github.com/michaeldmitry/flaplint/commit/0d91a2d84f7a06abd26d9f00ab1f2d96827cd7b7))
* add juju secrets as a sink ([3983f01](https://github.com/michaeldmitry/flaplint/commit/3983f01fc7bd1c3af17b9126e0188906194d4092))
* catch backrefs ([fbf0867](https://github.com/michaeldmitry/flaplint/commit/fbf08675981999ac1bc32cf1b40bffaf1405cb4e))
* constructor args type inference ([369bc66](https://github.com/michaeldmitry/flaplint/commit/369bc661a7b5587bf35ae9f7927ffdf7b2b416dc))
* explain-gaps flag ([7b6c755](https://github.com/michaeldmitry/flaplint/commit/7b6c75546bef717d220925d259048168282bee9e))
* flag more false neg ([429b1b1](https://github.com/michaeldmitry/flaplint/commit/429b1b175c534e54c4e0154b2edf4eec1b5cfb2b))
* own-only ([ae21e0b](https://github.com/michaeldmitry/flaplint/commit/ae21e0b42b4b8fb79d11ac604e2257a4a6754a87))
* pretty output ([30ecd3f](https://github.com/michaeldmitry/flaplint/commit/30ecd3fc49019916f81ac55231707560be081a01))
* support for instance attribute taint ([261ca83](https://github.com/michaeldmitry/flaplint/commit/261ca83a14078b0a7451913ed9d9b59fa8111601))
* value-object field provenance ([d025b46](https://github.com/michaeldmitry/flaplint/commit/d025b46815369a4bf281719fb044255cbbbd2adb))


### Bug Fixes

* agents.md ([0c5da2e](https://github.com/michaeldmitry/flaplint/commit/0c5da2e24c5d3bb69639ee0bd9a11096afd00702))
* anchor on ops public API + recognise ops list_files as an unordered source ([13e9221](https://github.com/michaeldmitry/flaplint/commit/13e9221f001d3625ac9ac18e28be9fa2c5e54b6a))
* bridge gaps for dataclasses/pydantic models, etc ([4bf9c33](https://github.com/michaeldmitry/flaplint/commit/4bf9c3387200f6a08af421d30f3d42f4eb3ab4a1))
* bridge some gaps reported by --explain-gaps ([c4beb67](https://github.com/michaeldmitry/flaplint/commit/c4beb6769c6b1c07cdd696cc7fdb5a4e576909e3))
* bridge val reached through a call gap ([8639a5c](https://github.com/michaeldmitry/flaplint/commit/8639a5ccfe14b24a9e89bbb68b507121e0193e38))
* CI ([defa07b](https://github.com/michaeldmitry/flaplint/commit/defa07bba9a3a863ac2b837bb06c8e369eea692c))
* enumerate blindspot ([970e40a](https://github.com/michaeldmitry/flaplint/commit/970e40ab9fb7142262060021d0db65ba7484396d))
* isinstance narrowing ([2609641](https://github.com/michaeldmitry/flaplint/commit/26096419fd181c354e32baab8304e4321a8c7d86))
* ops drift tests + docs on ops anchors drift ([cb50e83](https://github.com/michaeldmitry/flaplint/commit/cb50e833eeb4877450ebcd05c7ec21c992d16562))
* remove pebble.list_files from unorderd propagators ([6068d17](https://github.com/michaeldmitry/flaplint/commit/6068d177dc7b23dc8482d30ed1557c258d40b52e))
* two-level deep attribute access should carry the taint ([817485e](https://github.com/michaeldmitry/flaplint/commit/817485e4cbd912cd0b8d6eae5f5608971bbc0cba))
