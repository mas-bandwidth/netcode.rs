#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    netcode::fuzzing::private_connect_token_round_trip(data);
});
