use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{pallas, EqAffine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config, BLOCK_SIZE};

#[derive(Default)]
struct MyCircuit {}

impl Circuit<pallas::Base> for MyCircuit {
    type Config = Table16Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        Table16Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        Table16Chip::load(config.clone(), &mut layouter)?;
        let table16_chip = Table16Chip::construct(config);

        // Test vector: "abc"
        /*let input = [
            BlockWord(Value::known(0b01100001011000100110001110000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000011000)),
        ];*/

        //aa931f5ee58735270821b3722866d8882d1948909532cf8ac2b3ef144ae8043363d1d3728b49f10c7cd78c38289c8012477473879f3b53169f2a677b7fbed0c7
        /*
10101010100100110001111101011110
11100101100001110011010100100111
00001000001000011011001101110010
00101000011001101101100010001000
00101101000110010100100010010000
10010101001100101100111110001010
11000010101100111110111100010100
01001010111010000000010000110011
01100011110100011101001101110010
10001011010010011111000100001100
01111100110101111000110000111000
00101000100111001000000000010010
01000111011101000111001110000111
10011111001110110101001100010110
10011111001010100110011101111011
01111111101111101101000011000111
10000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000001000000000
         */
        let input = [
            BlockWord(Value::known(0b10101010100100110001111101011110)),
            BlockWord(Value::known(0b11100101100001110011010100100111)),
            BlockWord(Value::known(0b00001000001000011011001101110010)),
            BlockWord(Value::known(0b00101000011001101101100010001000)),
            BlockWord(Value::known(0b00101101000110010100100010010000)),
            BlockWord(Value::known(0b10010101001100101100111110001010)),
            BlockWord(Value::known(0b11000010101100111110111100010100)),
            BlockWord(Value::known(0b01001010111010000000010000110011)),
            BlockWord(Value::known(0b01100011110100011101001101110010)),
            BlockWord(Value::known(0b10001011010010011111000100001100)),
            BlockWord(Value::known(0b01111100110101111000110000111000)),
            BlockWord(Value::known(0b00101000100111001000000000010010)),
            BlockWord(Value::known(0b01000111011101000111001110000111)),
            BlockWord(Value::known(0b10011111001110110101001100010110)),
            BlockWord(Value::known(0b10011111001010100110011101111011)),
            BlockWord(Value::known(0b01111111101111101101000011000111)),
            BlockWord(Value::known(0b10000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000001000000000)),
        ];

        for i in 0..1 {
            Sha256::digest(table16_chip.clone(), layouter.namespace(|| "'publick key'"), &input)?;
        }

        Ok(())
    }
}

fn main() {
    println!("start test");
    // Initialize the polynomial commitment parameters
    let params_path = Path::new("./sha256_params");
    if File::open(params_path).is_err() {
        println!("start get param {:?}", chrono::offset::Utc::now());
        let params: Params<EqAffine> = Params::new(17);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
        println!("end   get param {:?}", chrono::offset::Utc::now());
    }

    let params_fs = File::open(params_path).expect("couldn't load sha256_params");
    let params: Params<EqAffine> =
        Params::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let empty_circuit: MyCircuit = MyCircuit {};

    // Initialize the proving key
    println!("start get kk {:?}", chrono::offset::Utc::now());
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    println!("end   get kk {:?}", chrono::offset::Utc::now());

    let circuit: MyCircuit = MyCircuit {};

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    println!("start get proof {:?}", chrono::offset::Utc::now());
    create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("proof generation should not fail");
    println!("end   get proof {:?}", chrono::offset::Utc::now());
    let proof: Vec<u8> = transcript.finalize();
    println!("proof size: {:?}", proof.len());

    let proof_path = Path::new("./sha256_proof");
    let mut file = File::create(&proof_path).expect("Failed to create sha256_proof");
    file.write_all(&proof[..]).expect("Failed to write proof");
}
