#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    netcode::fuzzing::packet_write_read_round_trip(data);
});
