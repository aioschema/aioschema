<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!--
     aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
     https://aioschema.org
-->

# License

Copyright 2026 Ovidiu Ancuta

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## Third-Party Dependencies

This implementation has **zero external NuGet dependencies**. All cryptographic
operations (Ed25519 signing and verification, SHA-256, SHA-384) use the .NET
runtime's built-in `System.Security.Cryptography` namespace, available in
.NET 5+ without any additional packages.

---

## AIOSchema Specification

The AIOSchema v0.5.6 specification is published at https://aioschema.org and is
licensed separately under the AIOSchema Specification License. This
implementation (the code in `implementations/dotnet/`) is independent of the
specification license and is provided under Apache-2.0.

<!-- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 -->
