/// Flutter FFI smoke stubs — documents the expected C ABI.
///
/// Link against `voce_e2ee_core` (`cargo build -p voce-e2ee-core --release`)
/// and call:
///
/// ```dart
/// final call = DynamicLibrary.open(lib)
///     .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
///         Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('voce_e2ee_call');
/// ```
///
/// This file is intentionally not a Dart package; it lives next to the Rust
/// crate for agents implementing Phase D.
library;

const voceE2eeFfiMethods = <String>[
  'version',
  'generate_identity',
  'generate_signed_prekey',
  'safety_number',
  'x3dh_initiator',
  'x3dh_responder',
  'envelope_v2_parse',
  'v1_decrypt',
];
