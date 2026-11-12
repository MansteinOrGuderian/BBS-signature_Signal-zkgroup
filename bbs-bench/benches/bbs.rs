// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) micro-benchmarks.
// Setting chosen to mirror a zkgroup AuthCredential: L = 4 attributes,
// 1 disclosed (e.g. redemption time), U = 3 hidden.
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use zkryptium::{
    keys::pair::KeyPair,
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256},
        generics::{PoKSignature, Signature},
    },
    utils::util::bbsplus_utils::{generate_random_secret, get_messages_vec},
};

type Cs = <BbsBls12381Sha256 as zkryptium::schemes::algorithms::Scheme>::Ciphersuite;

fn bench_bbs(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let ikm: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
    let kp = KeyPair::<BBSplus<Cs>>::generate(&ikm, None, None).unwrap();
    let (sk, pk) = (kp.private_key(), kp.public_key());
    let header = b"zkgroup-comparison".to_vec();
    let messages: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 32]).collect();
    let disclosed = [3usize];
    let nonce = generate_random_secret(32);

    let sig = Signature::<BBSplus<Cs>>::sign(Some(&messages), sk, pk, Some(&header)).unwrap();
    let proof = PoKSignature::<BBSplus<Cs>>::proof_gen(
        pk, &sig.to_bytes(), Some(&header), Some(&nonce), Some(&messages), Some(&disclosed),
    )
    .unwrap();
    let disclosed_msgs = get_messages_vec(&messages, &disclosed);
    println!("SIZES: public key = {} B, signature = {} B, proof (U=3) = {} B",
        pk.to_bytes().len(), sig.to_bytes().len(), proof.to_bytes().len());

    c.bench_function("bbs_sign_L4", |b| {
        b.iter(|| Signature::<BBSplus<Cs>>::sign(Some(&messages), sk, pk, Some(&header)).unwrap())
    });
    c.bench_function("bbs_verify_L4", |b| {
        b.iter(|| sig.verify(pk, Some(&messages), Some(&header)).unwrap())
    });
    c.bench_function("bbs_proof_gen_L4_U3", |b| {
        b.iter(|| {
            PoKSignature::<BBSplus<Cs>>::proof_gen(
                pk, &sig.to_bytes(), Some(&header), Some(&nonce), Some(&messages), Some(&disclosed),
            )
            .unwrap()
        })
    });
    c.bench_function("bbs_proof_verify_L4_U3", |b| {
        b.iter(|| {
            proof
                .proof_verify(pk, Some(&disclosed_msgs), Some(&disclosed), Some(&header), Some(&nonce))
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_bbs);
criterion_main!(benches);
