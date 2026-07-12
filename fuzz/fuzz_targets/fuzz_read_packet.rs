#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    netcode::fuzzing::read_packet_raw(data);
});
