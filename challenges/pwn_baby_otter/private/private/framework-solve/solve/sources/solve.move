module solution::baby_otter_solution {
    use sui::tx_context::TxContext;
    use challenge::baby_otter_challenge;

    public entry fun solve(status: &mut baby_otter_challenge::Status, ctx: &mut TxContext) {
        let secret_code : vector<u8> = vector[0x48, 0x34, 0x43, 0x4b];
        baby_otter_challenge::request_ownership(status, secret_code, ctx);
    }
}
